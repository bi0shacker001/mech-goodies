#!/usr/bin/env python3
"""
tailscale.py (Tailscale policy + tagging helper)

What it does:
- --pull: fetch current tailnet ACL policy JSON from the Tailscale API
- --in: read a local policy file (JSON/JSON5/HuJSON-ish via json5)
- --out: write a *pair* of files (pre/post) to disk (defaults to ~/.config/mech-goodies/tailscale/logs/)
- --validate: run read-only checks (default behavior anyway)
- --fix: apply fixes (policy edits and/or device tag edits), then re-validate
- --validate-remote: call Tailscale /acl/validate (read-only)
- --push: push updated policy back to the tailnet (only if validation is clean)
- --allow-all=(yes,no): yes ensures an allow-all grant exists at the top of "grants";
  no ensures there isn't. Omitted = no change.
- --grant-gc: (optional) remove unused tag:grant-* tagOwners + their associated policy grants (requires API; apply with --fix)

Services model:
- A service is defined by a service tag:
    tag:service-<service>
  And a global grant:
    src ["*"] -> dst ["tag:service-<service>"] with ip ["tcp:PORT", "udp:PORT", ...]
  Tagging a host with tag:service-<service> means "this host runs this service", and it is globally reachable
  by whatever the grants allow (the default "global grant" above allows everyone to reach it on those ports).

Adding services:
- --add service <name=ports> [name=ports ...]
  Example:
    --add service sonarr=8989/tcp radarr=7878 jellyfin=8096,8920

Ports spec syntax (for name=ports):
- Commas separate tokens only.
- Tokens can be:
    443              (expands to tcp:443 and udp:443)
    443/tcp          (tcp only)
    53/udp           (udp only)
    80-443           (expands to tcp:80-443 and udp:80-443)
    10000:10100      (range; ':' normalized to '-'; expands to tcp+udp)
- Advanced: you may also directly specify capability selectors:
    tcp:443,udp:53,tcp:80-443,icmp:*
  (Do not combine these with /tcp or /udp on the same token.)

Grant tags model (service access by client tags):
- A grant tag is:
    tag:grant-<service>-<clientTagValue>
  Example:
    tag:grant-sonarr-owner-alice
- Policy grants:
    src ["tag:<clientTagValue>"] -> dst ["tag:grant-<service>-<clientTagValue>"] with ip matching the service definition
- Tagging a host with tag:grant-<service>-<clientTagValue> means:
    "clients with <clientTagValue> may access <service> on this host"

Host-specific grant operations:
- --add grant <host>=<clientTag>:<svc,svc,...> [more...]
  Example:
    --add grant media-host-1=owner-alice:sonarr,radarr
- --rm grant <host>=<clientTag>:<svc,svc,...> [more...]
  Example:
    --rm grant media-host-1=owner-alice:sonarr

Devname workflow:
- --gen-devname-tags:
    - validate: detect missing tagOwners entries for tag:devname-<device>
    - fix: add missing devname tagOwners entries
- --autotag-devnames:
    - validate: detect devices missing their tag:devname-<device> tag
    - fix: apply missing devname tags to devices via API
    - note: device tagging may require pushing policy first so tagOwners exist remotely

Config precedence for tailnet/api-key/owner:
1) CLI flags
2) Environment variables
3) ~/.config/mech-goodies/tailscale.env
4) Hardcoded defaults below

tailscale.env example:
  # comments ok
  TAILSCALE_API_KEY=tskey-api-xxxxxxxx
  TAILSCALE_TAILNET=-
  TAILSCALE_OWNER_EMAIL=admin@example.com

Dependencies:
  pip install requests json5
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import json5
import requests

# ============================================================
# EASY-TO-FIND DEFAULTS (final fallback after CLI + env + file)
# ============================================================
DEFAULT_TAILNET = "-"         # "-" means "this token's tailnet"
DEFAULT_API_KEY = ""          # tskey-api-... (still sensitive)
DEFAULT_OWNER_EMAIL = ""      # intentionally blank: must be provided via env file/env var/flag

# Read extra variables from here (if present)
MECH_ENV_PATH = os.path.expanduser("~/.config/mech-goodies/tailscale.env")

# Output behavior
DEFAULT_LOG_DIR = os.path.expanduser("~/.config/mech-goodies/tailscale/logs")
WRITE_TIMESTAMPED_PAIR_BY_DEFAULT = True
DEFAULT_OUT_BASENAME = "tailnet-policy"

API_BASE = "https://api.tailscale.com"

BASE_PREFIXES = ("owner-", "devrole-", "ownerdept-", "devdept-", "devname-")
SERVICE_TAG_HEAD = "service-"  # tag value starts with "service-"
GRANT_TAG_HEAD = "grant-"      # tag value starts with "grant-"


# -----------------------------
# Models
# -----------------------------
@dataclass
class Issue:
    kind: str
    msg: str
    fixable: bool = True
    data: Optional[dict] = None


@dataclass
class PendingHostTagChange:
    host_ident: str
    add_tags: List[str]
    remove_tags: List[str]


# -----------------------------
# Config file parsing
# -----------------------------
def load_env_file(path: str) -> Dict[str, str]:
    """
    Parse a simple KEY=VALUE env file.
    Supports:
      - blank lines
      - comments starting with #
      - optional leading 'export '
      - quoted values "..." or '...'
    """
    out: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].strip()
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if not k:
                    continue
                if (len(v) >= 2) and ((v[0] == v[-1]) and v[0] in ("'", '"')):
                    v = v[1:-1]
                out[k] = v
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"WARNING: failed to read env file {path!r}: {e}", file=sys.stderr)
        return {}
    return out


MECH_ENV = load_env_file(MECH_ENV_PATH)


def cfg_get(key: str, default: str) -> str:
    """
    Precedence: OS env > mech env file > default
    (CLI flags are handled by argparse, so they win above this.)
    """
    return os.environ.get(key) or MECH_ENV.get(key) or default


# -----------------------------
# Small helpers
# -----------------------------
def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


def die(msg: str, code: int = 2) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def parse_device_tag_specs(tokens: Sequence[str]) -> List[Tuple[str, str]]:
    """
    Tokens:
      ["device-1=owner-alice,devrole-server", "device-2=devdept-lab"]
    Returns:
      [(device_ident, "owner-alice,devrole-server"), ...]
    """
    out: List[Tuple[str, str]] = []
    for tok in tokens:
        if "=" not in tok:
            die(f"--add/--rm tag expects device=tag,tag tokens, got: {tok!r}")
        dev, tags_csv = tok.split("=", 1)
        dev = dev.strip()
        tags_csv = tags_csv.strip()
        if not dev or not tags_csv:
            die(f"Invalid tag spec {tok!r}. Expected device=tag,tag")
        out.append((dev, tags_csv))
    return out


def normalize_tag_selector(tag: str) -> str:
    """
    Accepts:
      owner-alice
      tag:owner-alice
    Returns:
      tag:owner-alice (lowercased)
    """
    t = tag.strip()
    if not t:
        die("Empty tag provided.")
    if t.startswith("tag:"):
        t = t[4:]
    t = t.lower()

    # Commas are separators in lists, treat as invalid inside a tag for this tool.
    if "," in t:
        die(f"Tag contains a comma (commas are separators): {tag!r}")

    # Practical tag format: letters, digits, dashes; start with a letter.
    if not re.fullmatch(r"[a-z][a-z0-9-]*", t):
        die(f"Invalid tag name {tag!r}. Use letters/digits/dashes, starting with a letter.")

    return "tag:" + t


def tag_value(tag_selector: str) -> str:
    """tag:owner-alice -> owner-alice"""
    ts = normalize_tag_selector(tag_selector)
    return ts[4:]


def is_base_tag_selector(tag_selector: str) -> bool:
    v = tag_value(tag_selector)
    return any(v.startswith(p) for p in BASE_PREFIXES)


def is_owner_tag_selector(tag_selector: str) -> bool:
    return tag_value(tag_selector).startswith("owner-")


def normalize_grant_endpoint(sel: str) -> str:
    """
    For grants src/dst entries we allow:
      - "*" (all)
      - tag selectors (normalized)
      - autogroup:/group: entries (pass-through)
      - emails (pass-through)
    """
    s = sel.strip()
    if not s:
        die("Empty grant endpoint selector.")
    if s == "*":
        return "*"
    if s.startswith(("autogroup:", "group:")):
        return s
    if "@" in s and not s.startswith("tag:"):
        return s
    return normalize_tag_selector(s)


def normalize_ip_list(ip: List[str]) -> List[str]:
    # stable: unique then sort (string sort is fine for our canonical output)
    return sorted(set(ip))


def list_grant_tags(policy: Dict[str, Any]) -> List[str]:
    """
    Collect all tag:grant-* tags referenced by policy, from:
      - tagOwners keys
      - grants[*].dst
    """
    ensure_policy_shape(policy)
    found: set[str] = set()

    for t in (policy.get("tagOwners") or {}).keys():
        try:
            ts = normalize_tag_selector(t)
        except SystemExit:
            continue
        if parse_grant_tag(ts):
            found.add(ts)

    for g in policy.get("grants") or []:
        dsts = g.get("dst", [])
        if isinstance(dsts, list) and len(dsts) == 1 and isinstance(dsts[0], str):
            try:
                dst0 = normalize_tag_selector(dsts[0])
            except SystemExit:
                continue
            if parse_grant_tag(dst0):
                found.add(dst0)

    return sorted(found)


def collect_all_device_tags(tailnet: str, api_key: str) -> set[str]:
    """
    Union of all tags currently assigned to any device in the tailnet.
    """
    devices = api_list_devices(tailnet, api_key)
    used: set[str] = set()
    for d in devices:
        for t in merge_tag_list(d.get("tags", [])):
            used.add(t)
    return used


def collect_unused_grant_tag_issues(policy: Dict[str, Any], tailnet: str, api_key: str) -> List[Issue]:
    """
    Read-only: report tag:grant-* tags that exist in policy but are not assigned to any device.
    """
    ensure_policy_shape(policy)
    issues: List[Issue] = []

    policy_grant_tags = list_grant_tags(policy)
    if not policy_grant_tags:
        return issues

    used_device_tags = collect_all_device_tags(tailnet, api_key)

    for gt in policy_grant_tags:
        if gt not in used_device_tags:
            issues.append(Issue(
                kind="unused-grant-tag",
                msg=f"Grant tag {gt} is not assigned to any device; safe to remove from tagOwners and policy grants.",
                fixable=True,
                data={"tag": gt},
            ))

    return issues


def apply_grant_gc_fixes(policy: Dict[str, Any], issues: List[Issue]) -> List[str]:
    """
    Remove unused grant tags from:
      - tagOwners
      - policy grants where dst == [that tag]
    Returns notes.
    """
    ensure_policy_shape(policy)
    notes: List[str] = []

    to_remove: set[str] = set()
    for iss in issues:
        if iss.fixable and iss.kind == "unused-grant-tag" and iss.data and "tag" in iss.data:
            to_remove.add(normalize_tag_selector(iss.data["tag"]))

    if not to_remove:
        return notes

    # Remove from tagOwners
    for t in sorted(to_remove):
        if t in policy["tagOwners"]:
            policy["tagOwners"].pop(t, None)
            notes.append(f"grant-gc: removed tagOwners entry for {t}")

    # Remove from grants
    kept: List[Dict[str, Any]] = []
    removed_count = 0
    for g in policy.get("grants", []):
        dsts = g.get("dst", [])
        if isinstance(dsts, list) and len(dsts) == 1 and isinstance(dsts[0], str):
            try:
                dst0 = normalize_tag_selector(dsts[0])
            except SystemExit:
                kept.append(g)
                continue
            if dst0 in to_remove:
                removed_count += 1
                continue
        kept.append(g)

    if removed_count:
        notes.append(f"grant-gc: removed {removed_count} policy grant rule(s) targeting unused grant tags")

    policy["grants"] = kept
    return notes


def parse_ports_spec(ports_spec: str) -> List[str]:
    """
    Input examples:
      "8989"                  -> ["tcp:8989","udp:8989"]
      "8989/tcp"              -> ["tcp:8989"]
      "7878/udp"              -> ["udp:7878"]
      "80-443"                -> ["tcp:80-443","udp:80-443"]
      "10000:10100/tcp"       -> ["tcp:10000-10100"]
      "tcp:443,udp:53"        -> ["tcp:443","udp:53"]          (pass-through)
      "*", "*/tcp", "*/udp"   -> ["*"], ["tcp:*"], ["udp:*"]

    Only commas separate tokens.
    Port ranges accept '-' or ':' in input (':' is normalized to '-').
    Bare ports/ranges default to BOTH tcp+udp.
    """
    raw = ports_spec.strip()
    if not raw:
        die("Ports spec is empty.")

    parts = [p.strip() for p in raw.split(",") if p.strip()]
    out: List[str] = []
    seen: set[str] = set()

    def emit(s: str) -> None:
        s = s.lower()
        if s not in seen:
            out.append(s)
            seen.add(s)

    def validate_port(n: int) -> None:
        if not (1 <= n <= 65535):
            die(f"Port out of range: {n}")

    for tok in parts:
        # Optional suffix: /tcp or /udp
        proto_suffix: Optional[str] = None
        if "/" in tok:
            base, suf = tok.rsplit("/", 1)
            base = base.strip()
            suf = suf.strip().lower()
            if suf not in ("tcp", "udp"):
                die(f"Invalid protocol suffix {suf!r} in {tok!r}. Use /tcp or /udp.")
            proto_suffix = suf
            tok = base

        tok = tok.strip()
        if not tok:
            die("Empty token in ports spec.")

        # Direct capability selector pass-through (must not combine with /tcp or /udp)
        mcap = re.fullmatch(r"([a-z0-9]+):(\*|\d{1,5}|\d{1,5}-\d{1,5})", tok.lower())
        if mcap:
            if proto_suffix is not None:
                die(f"Do not combine proto selectors like {tok!r} with /tcp or /udp.")
            emit(tok.lower())
            continue

        # Wildcard
        if tok == "*":
            if proto_suffix is None:
                emit("*")
            else:
                emit(f"{proto_suffix}:*")
            continue

        # Normalize ":" to "-" for ranges like 10000:10100
        if ":" in tok and "-" not in tok:
            a, b = tok.split(":", 1)
            tok = f"{a}-{b}"

        # Single port
        if re.fullmatch(r"\d{1,5}", tok):
            port = int(tok)
            validate_port(port)
            if proto_suffix is None:
                emit(f"tcp:{port}")
                emit(f"udp:{port}")
            else:
                emit(f"{proto_suffix}:{port}")
            continue

        # Range
        m = re.fullmatch(r"(\d{1,5})-(\d{1,5})", tok)
        if m:
            a = int(m.group(1))
            b = int(m.group(2))
            validate_port(a)
            validate_port(b)
            if a > b:
                die(f"Port range start greater than end: {tok}")
            rng = f"{a}-{b}"
            if proto_suffix is None:
                emit(f"tcp:{rng}")
                emit(f"udp:{rng}")
            else:
                emit(f"{proto_suffix}:{rng}")
            continue

        die(f"Invalid port token {tok!r}. Use '443', '80-443', '80:443', '8989/tcp', or 'udp:53'.")

    return normalize_ip_list(out)


def parse_tags_csv(tags_csv: str) -> List[str]:
    raw = tags_csv.strip()
    if not raw:
        die("Tag CSV is empty.")
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return [normalize_tag_selector(p) for p in parts]


def ensure_policy_shape(policy: Dict[str, Any]) -> None:
    policy.setdefault("tagOwners", {})
    policy.setdefault("grants", [])
    policy.setdefault("acls", [])
    policy.setdefault("nodeAttrs", [])


def set_tag_owner(policy: Dict[str, Any], tag_selector: str, owner_email: str) -> None:
    ensure_policy_shape(policy)
    ts = normalize_tag_selector(tag_selector)
    policy["tagOwners"][ts] = [owner_email]


def remove_tag_owner(policy: Dict[str, Any], tag_selector: str) -> None:
    ensure_policy_shape(policy)
    ts = normalize_tag_selector(tag_selector)
    policy["tagOwners"].pop(ts, None)


def upsert_grant(policy: Dict[str, Any], src: str, dst: str, ip: List[str]) -> None:
    ensure_policy_shape(policy)
    src_s = normalize_grant_endpoint(src)
    dst_s = normalize_grant_endpoint(dst)
    ip_n = normalize_ip_list(ip)
    desired = {"src": [src_s], "dst": [dst_s], "ip": ip_n}

    grants: List[Dict[str, Any]] = policy["grants"]
    for g in grants:
        if g.get("src") == [src_s] and g.get("dst") == [dst_s]:
            g["ip"] = ip_n
            return
    grants.append(desired)


def grant_exists(policy: Dict[str, Any], src: str, dst: str, ip: Optional[List[str]] = None) -> bool:
    ensure_policy_shape(policy)
    src_s = normalize_grant_endpoint(src)
    dst_s = normalize_grant_endpoint(dst)
    for g in policy["grants"]:
        if g.get("src") == [src_s] and g.get("dst") == [dst_s]:
            if ip is None:
                return True
            if isinstance(g.get("ip"), list) and normalize_ip_list(list(g["ip"])) == normalize_ip_list(list(ip)):
                return True
    return False


def find_service_definition_grants(policy: Dict[str, Any], service_tag: str) -> List[Tuple[int, Dict[str, Any]]]:
    """
    Return a list of (index, grant) for the global service-definition grants:
      src == ["*"] and dst == [tag:service-<service>]

    Note: tagOwners cannot contain duplicates (JSON object keys), so duplication only happens
    in the policy["grants"] list.
    """
    ensure_policy_shape(policy)
    st = normalize_tag_selector(service_tag)

    out: List[Tuple[int, Dict[str, Any]]] = []
    grants = policy.get("grants", [])
    if not isinstance(grants, list):
        return out

    for i, g in enumerate(grants):
        if not isinstance(g, dict):
            continue
        if g.get("src") == ["*"] and g.get("dst") == [st]:
            out.append((i, g))

    return out


def list_base_tags(policy: Dict[str, Any]) -> List[str]:
    ensure_policy_shape(policy)
    tags: List[str] = []
    for t in policy["tagOwners"].keys():
        try:
            if is_base_tag_selector(t):
                tags.append(normalize_tag_selector(t))
        except SystemExit:
            continue
    return sorted(set(tags))


def parse_service_tag(tag_selector: str) -> Optional[str]:
    """
    tag:service-<service>
    Returns: service name
    """
    ts = normalize_tag_selector(tag_selector)
    v = tag_value(ts)  # e.g. "service-sonarr"
    if not v.startswith(SERVICE_TAG_HEAD):
        return None
    service = v[len(SERVICE_TAG_HEAD):]
    if not re.fullmatch(r"[a-z][a-z0-9-]*", service):
        return None
    return service


def parse_grant_tag(tag_selector: str) -> Optional[Tuple[str, str]]:
    """
    tag:grant-<service>-<clientTagValue>
    clientTagValue is expected to start with one of BASE_PREFIXES.

    Returns: (service, clientTagValue)
    """
    ts = normalize_tag_selector(tag_selector)
    v = tag_value(ts)  # e.g. "grant-sonarr-owner-alice"
    if not v.startswith(GRANT_TAG_HEAD):
        return None

    rest = v[len(GRANT_TAG_HEAD):]  # "sonarr-owner-alice"
    for base_prefix in BASE_PREFIXES:
        marker = "-" + base_prefix
        idx = rest.rfind(marker)
        if idx > 0:
            service = rest[:idx]
            client_val = rest[idx + 1:]
            if re.fullmatch(r"[a-z][a-z0-9-]*", service) and re.fullmatch(r"[a-z][a-z0-9-]*", client_val):
                return (service, client_val)
    return None


def list_services(policy: Dict[str, Any]) -> List[str]:
    ensure_policy_shape(policy)
    services = set()

    # Discover from tagOwners
    for t in policy["tagOwners"].keys():
        svc = parse_service_tag(t)
        if svc:
            services.add(svc)

    # Discover from grants too
    for g in policy["grants"]:
        dsts = g.get("dst")
        if isinstance(dsts, list) and len(dsts) == 1 and isinstance(dsts[0], str):
            svc = parse_service_tag(dsts[0])  # service tags can be a dst
            if svc:
                services.add(svc)

    return sorted(services)


def service_tag_for(service: str) -> str:
    return normalize_tag_selector(f"service-{service}")


def grant_tag_for(service: str, client_tag_value: str) -> str:
    return normalize_tag_selector(f"grant-{service}-{client_tag_value}")


def infer_service_ip_from_grants(policy: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Canonical ports per service inferred from existing grants where:
      dst == [tag:service-<service>]
    """
    ensure_policy_shape(policy)
    service_ip: Dict[str, List[str]] = {}

    for g in policy["grants"]:
        dsts = g.get("dst", [])
        if not (isinstance(dsts, list) and len(dsts) == 1 and isinstance(dsts[0], str)):
            continue
        svc = parse_service_tag(dsts[0])
        if not svc:
            continue
        ip = g.get("ip", [])
        if isinstance(ip, list) and ip and svc not in service_ip:
            service_ip[svc] = normalize_ip_list(list(ip))

    return service_ip


def list_devname_tags(policy: Dict[str, Any]) -> List[str]:
    ensure_policy_shape(policy)
    out: List[str] = []
    for t in policy["tagOwners"].keys():
        try:
            ts = normalize_tag_selector(t)
        except SystemExit:
            continue
        v = tag_value(ts)
        if v.startswith("devname-"):
            out.append(ts)
    return sorted(set(out))


# -----------------------------
# Allow-all grant toggling
# -----------------------------
ALLOW_ALL_GRANT = {"src": ["*"], "dst": ["*"], "ip": ["*"]}


def is_allow_all_grant(g: Any) -> bool:
    if not isinstance(g, dict):
        return False
    if g.get("src") != ["*"] or g.get("dst") != ["*"] or g.get("ip") != ["*"]:
        return False
    # Don't treat posture/via/app rules as the canonical allow-all.
    for k in ("app", "via", "srcPosture"):
        if k in g and g.get(k):
            return False
    return True


def apply_allow_all_setting(policy: Dict[str, Any], mode: Optional[str]) -> List[str]:
    """
    mode:
      - "yes": ensure allow-all grant exists and is the first grant
      - "no": ensure no allow-all grant exists
      - None: do nothing
    Returns notes about what changed.
    """
    if mode is None:
        return []

    ensure_policy_shape(policy)
    if not isinstance(policy.get("grants"), list):
        policy["grants"] = []

    grants: List[Dict[str, Any]] = policy["grants"]
    allow_all = [g for g in grants if is_allow_all_grant(g)]
    others = [g for g in grants if not is_allow_all_grant(g)]
    notes: List[str] = []

    if mode == "yes":
        if allow_all:
            keep = allow_all[0]
            if grants and grants[0] is keep:
                notes.append("already present at top")
            else:
                notes.append("moved to top")
            if len(allow_all) > 1:
                notes.append(f"removed {len(allow_all) - 1} duplicate(s)")
        else:
            keep = copy.deepcopy(ALLOW_ALL_GRANT)
            notes.append("added")
        policy["grants"] = [keep] + others
        return notes

    if mode == "no":
        if allow_all:
            policy["grants"] = others
            notes.append(f"removed {len(allow_all)}")
        else:
            notes.append("already absent")
        return notes

    die("--allow-all must be 'yes' or 'no' (or omitted).")
    return []


# -----------------------------
# API layer
# -----------------------------
def api_req(
    method: str,
    path: str,
    api_key: str,
    *,
    json_body: Any = None,
    data_body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> requests.Response:
    url = API_BASE + path
    h = dict(headers or {})
    auth = (api_key, "")
    return requests.request(method, url, auth=auth, json=json_body, data=data_body, headers=h, timeout=30)


def api_pull_policy(tailnet: str, api_key: str) -> Dict[str, Any]:
    resp = api_req("GET", f"/api/v2/tailnet/{tailnet}/acl", api_key)
    if resp.status_code != 200:
        die(f"Pull policy failed: HTTP {resp.status_code} {resp.text[:300]}")

    text = resp.text.strip()
    ct = resp.headers.get("content-type", "")
    if "application/json" in ct:
        try:
            obj = resp.json()
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass

    try:
        return json5.loads(text)
    except Exception as e:
        die(f"Could not parse pulled policy as JSON/JSON5/HuJSON: {e}")


def api_validate_policy(tailnet: str, api_key: str, policy: Dict[str, Any]) -> None:
    body = json.dumps(policy, indent=2).encode("utf-8")
    resp = api_req(
        "POST",
        f"/api/v2/tailnet/{tailnet}/acl/validate",
        api_key,
        data_body=body,
        headers={"content-type": "application/json"},
    )
    if resp.status_code != 200:
        die(f"Policy validate failed: HTTP {resp.status_code}\n{resp.text}")


def api_push_policy(tailnet: str, api_key: str, policy: Dict[str, Any]) -> None:
    body = json.dumps(policy, indent=2).encode("utf-8")
    resp = api_req(
        "POST",
        f"/api/v2/tailnet/{tailnet}/acl",
        api_key,
        data_body=body,
        headers={"content-type": "application/json"},
    )
    if resp.status_code != 200:
        die(f"Policy push failed: HTTP {resp.status_code}\n{resp.text}")


def api_list_devices(tailnet: str, api_key: str) -> List[Dict[str, Any]]:
    resp = api_req("GET", f"/api/v2/tailnet/{tailnet}/devices", api_key)
    if resp.status_code != 200:
        die(f"List devices failed: HTTP {resp.status_code} {resp.text[:300]}")
    obj = resp.json()
    if isinstance(obj, dict) and isinstance(obj.get("devices"), list):
        return obj["devices"]
    if isinstance(obj, list):
        return obj
    die("Unexpected device list response shape.")


def api_set_device_tags(device_id: str, api_key: str, tags: List[str]) -> None:
    payload = {"tags": tags}
    resp = api_req("POST", f"/api/v2/device/{device_id}/tags", api_key, json_body=payload)
    if resp.status_code != 200:
        die(f"Set device tags failed for device {device_id}: HTTP {resp.status_code}\n{resp.text}")


# -----------------------------
# Canonical naming / matching
# -----------------------------
def strip_tsnet_tailnet_suffix(s: str) -> str:
    """
    Strip '<two-words>.ts.net' suffix if present.

    Handles:
      - FQDN:  host.lemur-paradise.ts.net  -> host
      - Dashed: host-lemur-paradise-ts-net -> host
    """
    s = s.strip()

    # FQDN form
    m = re.search(r"\.([a-z0-9]+-[a-z0-9]+)\.ts\.net$", s, flags=re.IGNORECASE)
    if m:
        return s[:m.start()]

    # Dashed form
    m = re.search(r"-([a-z0-9]+-[a-z0-9]+)-ts-net$", s, flags=re.IGNORECASE)
    if m:
        return s[:m.start()]

    return s


def canonical_device_name(d: Dict[str, Any]) -> Optional[str]:
    """
    Canonical name = admin console "name".
    MagicDNS is derived from this, so we intentionally do NOT use dnsName here.
    """
    v = d.get("name")
    if isinstance(v, str) and v.strip():
        return strip_tsnet_tailnet_suffix(v.strip())
    return None


def device_match_fields(d: Dict[str, Any]) -> List[str]:
    fields: List[str] = []
    for k in ("name", "hostname", "hostName", "machineName", "dnsName"):
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            fields.append(strip_tsnet_tailnet_suffix(v.strip()))
    return fields


def find_devices_by_ident(devices: List[Dict[str, Any]], ident: str) -> List[Dict[str, Any]]:
    ident = ident.strip()
    if not ident:
        return []
    if ident.isdigit():
        return [d for d in devices if str(d.get("id", "")).strip() == ident]

    target = ident.lower()
    matches: List[Dict[str, Any]] = []
    for d in devices:
        fields_l = [f.lower() for f in device_match_fields(d)]
        if target in fields_l:
            matches.append(d)
            continue
        for f in fields_l:
            if f.startswith(target + "."):
                matches.append(d)
                break
    return matches


def merge_tag_list(existing: Any) -> List[str]:
    if not isinstance(existing, list):
        return []
    out: List[str] = []
    for t in existing:
        if isinstance(t, str) and t.strip():
            out.append(normalize_tag_selector(t))
    return sorted(set(out))


# -----------------------------
# Devname tag generation
# -----------------------------
def sanitize_for_tag_component(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-{2,}", "-", s)
    s = s.strip("-")
    return s or "unknown"


def devname_tag_for_device_name(name: str) -> str:
    comp = sanitize_for_tag_component(name)
    return normalize_tag_selector(f"devname-{comp}")


def desired_devname_tags_from_devices(devices: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    notes: List[str] = []
    mapping: Dict[str, List[str]] = {}

    for d in devices:
        raw = canonical_device_name(d)
        if not raw:
            notes.append("gen-devname-tags: skipped a device with no usable admin-console name")
            continue
        tag = devname_tag_for_device_name(raw)
        mapping.setdefault(tag, []).append(raw)

    desired: List[str] = []
    for tag, raws in sorted(mapping.items()):
        if len(raws) == 1:
            desired.append(tag)
        else:
            notes.append(f"gen-devname-tags: collision for {tag}: raw names={raws} (skipping; resolve manually)")
    return desired, notes


def collect_missing_devname_tagowners(policy: Dict[str, Any], desired_devname_tags: List[str]) -> List[Issue]:
    ensure_policy_shape(policy)
    issues: List[Issue] = []
    existing = set(policy["tagOwners"].keys())
    for dt in desired_devname_tags:
        dt = normalize_tag_selector(dt)
        if dt not in existing:
            issues.append(Issue(
                kind="missing-devname-tagowner",
                msg=f"Missing tagOwners entry for {dt}.",
                fixable=True,
                data={"tag": dt},
            ))
    return issues


def apply_missing_devname_tagowners(policy: Dict[str, Any], owner_email: str, issues: List[Issue]) -> List[str]:
    ensure_policy_shape(policy)
    notes: List[str] = []
    for iss in issues:
        if not iss.fixable or iss.kind != "missing-devname-tagowner" or not iss.data:
            continue
        tag = iss.data["tag"]
        if tag not in policy["tagOwners"]:
            policy["tagOwners"][tag] = [owner_email]
            notes.append(f"fix: added tagOwner for {tag}")
    return notes


# -----------------------------
# Ops: add/rm base/service/tag/grant
# -----------------------------
def add_base(policy: Dict[str, Any], owner_email: str, tags: Sequence[str]) -> None:
    if not tags:
        die("--add base requires at least 1 tag")
    for t in tags:
        set_tag_owner(policy, normalize_tag_selector(t), owner_email)


def rm_base(policy: Dict[str, Any], tags: Sequence[str]) -> None:
    if not tags:
        die("--rm base requires at least 1 tag")
    norm = [normalize_tag_selector(t) for t in tags]

    for t in norm:
        remove_tag_owner(policy, t)

    # Also remove grant tags that reference removed base tags (clientTagValue)
    base_values = {tag_value(t) for t in norm}

    def is_grant_for_removed_base(tag_sel: str) -> bool:
        parsed = parse_grant_tag(tag_sel)
        return bool(parsed and parsed[1] in base_values)

    for t in list(policy.get("tagOwners", {}).keys()):
        if is_grant_for_removed_base(t):
            policy["tagOwners"].pop(t, None)

    base_set = set(norm)
    kept = []
    for g in policy.get("grants", []):
        srcs = g.get("src", [])
        dsts = g.get("dst", [])

        if not isinstance(srcs, list) or not isinstance(dsts, list) or not srcs or not dsts:
            kept.append(g)
            continue

        # Remove grants whose src is a removed base tag
        if len(srcs) == 1 and srcs[0] in base_set:
            continue

        # Remove grants whose dst is a grant tag for a removed base tag
        if len(dsts) == 1 and is_grant_for_removed_base(dsts[0]):
            continue

        kept.append(g)
    policy["grants"] = kept


def add_service(policy: Dict[str, Any], owner_email: str, service: str, ports_spec: str) -> None:
    svc = service.strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9-]*", svc):
        die("Service name must be letters/digits/dashes, starting with a letter.")
    ip = parse_ports_spec(ports_spec)

    st = service_tag_for(svc)
    set_tag_owner(policy, st, owner_email)

    dups = find_service_definition_grants(policy, st)
    if len(dups) > 1:
        print(
            f"WARNING: service '{svc}' already has {len(dups)} global definition grants for dst [{st}]. "
            "Validation/--fix can deduplicate them."
        )

    # Global service definition grant: everyone -> service tag on these ports
    upsert_grant(policy, src="*", dst=st, ip=ip)


def rm_service(policy: Dict[str, Any], service: str) -> None:
    svc = service.strip().lower()
    if not svc:
        die("Service name is empty.")
    ensure_policy_shape(policy)

    st = service_tag_for(svc)
    policy["tagOwners"].pop(st, None)

    # Remove grant tags for this service
    to_remove = []
    for t in list(policy["tagOwners"].keys()):
        parsed = parse_grant_tag(t)
        if parsed and parsed[0] == svc:
            to_remove.append(t)
    for t in to_remove:
        policy["tagOwners"].pop(t, None)

    # Remove grants whose dst is the service tag or any of its grant tags
    kept = []
    for g in policy["grants"]:
        dsts = g.get("dst", [])
        if isinstance(dsts, list) and len(dsts) == 1 and isinstance(dsts[0], str):
            dst0 = dsts[0]
            if normalize_grant_endpoint(dst0) == st:
                continue
            parsed = parse_grant_tag(dst0)
            if parsed and parsed[0] == svc:
                continue
        kept.append(g)
    policy["grants"] = kept


def parse_service_specs(tokens: Sequence[str]) -> List[Tuple[str, str]]:
    specs: List[Tuple[str, str]] = []
    for tok in tokens:
        if "=" not in tok:
            die(f"--add service expects name=ports tokens, got: {tok!r}")
        name, ports = tok.split("=", 1)
        name = name.strip()
        ports = ports.strip()
        if not name or not ports:
            die(f"Invalid service spec {tok!r}. Expected name=ports.")
        specs.append((name, ports))
    return specs


def parse_grant_specs(tokens: Sequence[str]) -> List[Tuple[str, str, List[str]]]:
    """
    Each token: <host>=<clientTag>:<svc,svc,...>
      media-host-1=owner-alice:sonarr,radarr
    Returns: [(host_ident, client_tag_selector, [services...]), ...]
    """
    out: List[Tuple[str, str, List[str]]] = []
    for tok in tokens:
        if "=" not in tok:
            die(f"--add/--rm grant expects host=clientTag:svc,svc tokens, got: {tok!r}")
        host, rhs = tok.split("=", 1)
        host = host.strip()
        rhs = rhs.strip()
        if not host or not rhs or ":" not in rhs:
            die(f"Invalid grant spec {tok!r}. Expected host=clientTag:svc,svc")
        client, svcs = rhs.split(":", 1)
        client = normalize_tag_selector(client.strip())
        svcs_list = [s.strip().lower() for s in svcs.split(",") if s.strip()]
        if not svcs_list:
            die(f"Invalid grant spec {tok!r}: no services listed.")
        for s in svcs_list:
            if not re.fullmatch(r"[a-z][a-z0-9-]*", s):
                die(f"Invalid service name {s!r} in {tok!r}. Use letters/digits/dashes, starting with a letter.")
        out.append((host, client, svcs_list))
    return out


def service_ports_or_die(policy: Dict[str, Any], service: str) -> List[str]:
    st = service_tag_for(service)
    if st not in policy.get("tagOwners", {}):
        die(f"Service tag {st} does not exist in tagOwners. Define it first with --add service {service}=<ports>")

    service_ip = infer_service_ip_from_grants(policy)
    ip = service_ip.get(service)
    if not ip:
        die(f"Service '{service}' has no inferable ports (no grant with dst [{st}] and ip). Re-add service with ports.")
    return ip


def ensure_grant_tag_and_rule(policy: Dict[str, Any], owner_email: str, client_tag: str, service: str) -> str:
    """
    Ensure:
      - tagOwners has tag:grant-<service>-<clientTagValue>
      - grants contains client_tag -> grant_tag with ip matching service definition
    Returns the grant_tag selector.
    """
    ensure_policy_shape(policy)

    # client_tag must exist as a base tag in tagOwners (we use it as src)
    if client_tag not in policy.get("tagOwners", {}):
        die(f"Client tag {client_tag} is not defined in tagOwners. Add it via --add base ... first.")

    ip = service_ports_or_die(policy, service)

    client_val = tag_value(client_tag)
    gt = grant_tag_for(service, client_val)
    set_tag_owner(policy, gt, owner_email)

    if not grant_exists(policy, src=client_tag, dst=gt, ip=ip):
        upsert_grant(policy, src=client_tag, dst=gt, ip=ip)

    return gt


def add_or_rm_device_tags(
    policy: Dict[str, Any],
    owner_email: str,
    *,
    tailnet: str,
    api_key: str,
    device_ident: str,
    tags_csv: str,
    remove: bool,
    allow_owner_change: bool,
    fix_enabled: bool,
) -> None:
    """
    Applies device tags if fix_enabled, otherwise prints a dry-run diff.

    Note: This function also ensures the tags exist in tagOwners (policy side),
    because Tailscale requires tagOwners for tagged nodes.
    """
    tags = parse_tags_csv(tags_csv)

    # Ensure tags exist in tagOwners so they can be applied.
    for t in tags:
        set_tag_owner(policy, t, owner_email)

    devices = api_list_devices(tailnet, api_key)

    matches = find_devices_by_ident(devices, device_ident)
    if not matches:
        die(f"No device found matching {device_ident!r}. Use an exact device name (or numeric id).")
    if len(matches) > 1:
        ids = ", ".join(str(m.get("id")) for m in matches)
        die(f"Device identifier matched multiple devices (ids: {ids}). Use a numeric id.")

    dev = matches[0]
    dev_id = str(dev.get("id", "")).strip()
    if not dev_id:
        die("Device record has no 'id' field; cannot tag.")

    current_norm = merge_tag_list(dev.get("tags", []))

    # Enforce: at most one owner-* in the *requested* tags
    owner_requested = [t for t in tags if is_owner_tag_selector(t)]
    if len(owner_requested) > 1:
        die(f"Refusing to specify multiple owner-* tags in one operation: {owner_requested}")

    # Identify current owner tags (could be 0 or >1 if already messy)
    current_owner = [t for t in current_norm if is_owner_tag_selector(t)]

    if remove:
        # Only owner tag removals are gated. If not allowed, skip owner removal but still remove other tags.
        removing_owner = any(is_owner_tag_selector(t) for t in tags)
        if removing_owner and current_owner:
            if not fix_enabled:
                print(f"owner-tag: would remove {current_owner} from device '{device_ident}'")
                tags = [t for t in tags if not is_owner_tag_selector(t)]
            elif not allow_owner_change:
                print(
                    f"owner-tag: would remove {current_owner} from device '{device_ident}' "
                    f"(skipped; missing --allow-owner-change)"
                )
                tags = [t for t in tags if not is_owner_tag_selector(t)]

        new_tags = [t for t in current_norm if t not in tags]

    else:
        # Only owner tag replacement/normalization is gated. If not allowed, skip owner change but still add other tags.
        if owner_requested:
            new_owner = owner_requested[0]
            replacing = any(t != new_owner for t in current_owner)
            messy = len(current_owner) > 1

            if current_owner and (replacing or messy):
                if not fix_enabled:
                    if replacing:
                        print(f"owner-tag: would replace {current_owner} -> {new_owner} on device '{device_ident}'")
                    else:
                        print(
                            f"owner-tag: would normalize multiple owners {current_owner} -> {new_owner} "
                            f"on device '{device_ident}'"
                        )
                    tags = [t for t in tags if not is_owner_tag_selector(t)]

                elif not allow_owner_change:
                    if replacing:
                        print(
                            f"owner-tag: would replace {current_owner} -> {new_owner} on device '{device_ident}' "
                            f"(skipped; missing --allow-owner-change)"
                        )
                    else:
                        print(
                            f"owner-tag: would normalize multiple owners {current_owner} -> {new_owner} "
                            f"on device '{device_ident}' (skipped; missing --allow-owner-change)"
                        )
                    tags = [t for t in tags if not is_owner_tag_selector(t)]

                else:
                    if replacing:
                        print(f"owner-tag: replacing {current_owner} -> {new_owner} on device '{device_ident}'")
                    elif messy:
                        print(
                            f"owner-tag: normalizing multiple owners {current_owner} -> {new_owner} "
                            f"on device '{device_ident}'"
                        )

                    # Allowed: enforce single owner by removing all existing owner tags
                    current_norm = [t for t in current_norm if not is_owner_tag_selector(t)]

        new_tags = sorted(set(current_norm).union(tags))

    added = sorted(set(new_tags) - set(current_norm))
    removed = sorted(set(current_norm) - set(new_tags))

    if not fix_enabled:
        if added or removed:
            print(f"device-tag: would update '{device_ident}' (id {dev_id}) add={added} remove={removed}")
        else:
            print(f"device-tag: no changes for '{device_ident}' (id {dev_id})")
        return

    if new_tags == current_norm:
        return

    api_set_device_tags(dev_id, api_key, new_tags)


def apply_pending_host_tag_changes(changes: List[PendingHostTagChange], tailnet: str, api_key: str) -> List[str]:
    notes: List[str] = []
    if not changes:
        return notes

    devices = api_list_devices(tailnet, api_key)

    for ch in changes:
        matches = find_devices_by_ident(devices, ch.host_ident)
        if not matches:
            die(f"No host device found matching {ch.host_ident!r} (for grant tagging).")
        if len(matches) > 1:
            ids = ", ".join(str(m.get("id")) for m in matches)
            die(f"Host identifier {ch.host_ident!r} matched multiple devices (ids: {ids}). Use a numeric id.")

        dev = matches[0]
        dev_id = str(dev.get("id", "")).strip()
        if not dev_id:
            die(f"Host device {ch.host_ident!r} has no 'id' field; cannot tag.")

        current = merge_tag_list(dev.get("tags", []))
        add = [normalize_tag_selector(t) for t in ch.add_tags]
        rem = [normalize_tag_selector(t) for t in ch.remove_tags]

        new = sorted(set(current).union(add))
        new = [t for t in new if t not in set(rem)]

        if new == current:
            continue

        api_set_device_tags(dev_id, api_key, new)
        display = dev.get("name") or dev.get("hostname") or ch.host_ident
        if add:
            notes.append(f"fix-grants: added {add} on host '{display}' (id {dev_id})")
        if rem:
            notes.append(f"fix-grants: removed {rem} on host '{display}' (id {dev_id})")

    return notes


# -----------------------------
# Validation (read-only) + Fix
# -----------------------------
def collect_policy_issues(policy: Dict[str, Any]) -> List[Issue]:
    """
    Read-only:
      - Services must have ports (inferable from grants to tag:service-<service>)
      - Services should have exactly one global definition grant
      - Grant tags must have matching per-client grants and correct ip
      - If a grant tag refers to a missing service tag, error (not fixable)
    """
    ensure_policy_shape(policy)
    issues: List[Issue] = []

    services = list_services(policy)
    service_ip = infer_service_ip_from_grants(policy)

    for s in services:
        st = service_tag_for(s)

        # Each service must have a canonical port definition (inferred from its global definition grant).
        if s not in service_ip:
            issues.append(
                Issue(
                    kind="service-missing-ports",
                    msg=f"Service '{s}' has no inferable canonical ports (no grants with dst [{st}] and ip).",
                    fixable=False,
                    data={"service": s},
                )
            )

        # Detect duplicate global definition grants for the service.
        dups = find_service_definition_grants(policy, st)
        if len(dups) > 1:
            candidates: List[Dict[str, Any]] = []
            for idx, g in dups:
                ip_raw = g.get("ip", [])
                ip_n = normalize_ip_list(list(ip_raw)) if isinstance(ip_raw, list) else []
                extras = sorted(k for k in g.keys() if k not in ("src", "dst", "ip"))
                candidates.append({"index": idx, "ip": ip_n, "extras": extras})

            issues.append(
                Issue(
                    kind="duplicate-service-definition-grants",
                    msg=f"Service '{s}' has {len(dups)} global definition grants for dst [{st}] (should be exactly 1).",
                    fixable=True,
                    data={"service": s, "service_tag": st, "candidates": candidates},
                )
            )

    # Walk all grant tags we know about: from tagOwners and grants
    grant_tags: set[str] = set()
    for t in policy.get("tagOwners", {}).keys():
        if parse_grant_tag(t):
            grant_tags.add(normalize_tag_selector(t))
    for g in policy.get("grants", []):
        dsts = g.get("dst", [])
        if isinstance(dsts, list) and len(dsts) == 1 and isinstance(dsts[0], str):
            if parse_grant_tag(dsts[0]):
                grant_tags.add(normalize_tag_selector(dsts[0]))

    for gt in sorted(grant_tags):
        parsed = parse_grant_tag(gt)
        if not parsed:
            continue
        service, client_val = parsed
        st = service_tag_for(service)

        if st not in policy.get("tagOwners", {}):
            issues.append(
                Issue(
                    kind="grant-missing-service",
                    msg=f"Grant tag {gt} refers to service '{service}', but {st} is not defined in tagOwners.",
                    fixable=False,
                    data={"grant_tag": gt, "service": service},
                )
            )
            continue

        ip = service_ip.get(service)
        if not ip:
            # service-missing-ports already captured; don't duplicate too much
            continue

        client_tag = normalize_tag_selector(client_val)
        if client_tag not in policy.get("tagOwners", {}):
            issues.append(
                Issue(
                    kind="grant-missing-client-tagowner",
                    msg=f"Grant tag {gt} refers to client tag {client_tag}, but it is not defined in tagOwners.",
                    fixable=False,
                    data={"grant_tag": gt, "client_tag": client_tag},
                )
            )
            continue

        if gt not in policy.get("tagOwners", {}):
            issues.append(
                Issue(
                    kind="missing-grant-tagowner",
                    msg=f"Missing tagOwners entry for {gt}.",
                    fixable=True,
                    data={"tag": gt},
                )
            )

        if not grant_exists(policy, src=client_tag, dst=gt, ip=ip):
            issues.append(
                Issue(
                    kind="missing-grant",
                    msg=f"Missing or mismatched grant {client_tag} -> {gt} with ip={ip} (should match service '{service}').",
                    fixable=True,
                    data={"src": client_tag, "dst": gt, "ip": ip},
                )
            )

    return issues


def dedup_service_definition_grants_prompt(policy: Dict[str, Any], service: str) -> List[str]:
    """
    Interactive fixer for duplicate service definition grants.

    A service definition grant is:
      src ["*"] -> dst [tag:service-<service>]

    If multiple exist, this prompts you to keep one, optionally merging ports.
    """
    ensure_policy_shape(policy)
    svc = service.strip().lower()
    st = service_tag_for(svc)

    dups = find_service_definition_grants(policy, st)
    if len(dups) <= 1:
        return []

    if not sys.stdin.isatty():
        die(
            f"Need interactive input to deduplicate service definition grants for '{svc}'. "
            "Run in an interactive terminal, or deduplicate manually."
        )

    print("")
    print(f"Service '{svc}' has {len(dups)} duplicate global definition grants (src ['*'] -> dst [{st}]).")

    entries: List[Dict[str, Any]] = []
    for n, (idx, g) in enumerate(dups):
        ip_raw = g.get("ip", [])
        ip_n = normalize_ip_list(list(ip_raw)) if isinstance(ip_raw, list) else []
        extras = sorted(k for k in g.keys() if k not in ("src", "dst", "ip"))
        extra_s = f" extras={extras}" if extras else ""
        print(f"  [{n}] policy_index={idx} ip={ip_n}{extra_s}")
        entries.append({"n": n, "idx": idx, "ip": ip_n})

    prompt = (
        "Choose: 'm=<n>' merge ports into entry n (default m=0), "
        "'k=<n>' keep only entry n, or 'a' abort: "
    )

    while True:
        ans = input(prompt).strip().lower()
        if ans == "":
            ans = "m=0"

        if ans in ("a", "abort"):
            return [f"dedup-service: skipped '{svc}' at user request"]

        m = re.fullmatch(r"([mk])=([0-9]+)", ans)
        if not m:
            print("Invalid choice. Examples: m=0, k=1, a")
            continue

        mode = m.group(1)
        n = int(m.group(2))
        if n < 0 or n >= len(entries):
            print(f"Index out of range. Choose 0..{len(entries) - 1}.")
            continue

        keep_policy_idx = entries[n]["idx"]

        # Merge ports into the kept entry (if requested).
        if mode == "m":
            merged: set[str] = set()
            for e in entries:
                merged.update(e["ip"])

            kept = policy["grants"][keep_policy_idx]
            kept["ip"] = normalize_ip_list(list(merged))

        # Remove duplicates (descending indices so earlier pops don't shift later ones).
        remove_indices = sorted([e["idx"] for e in entries if e["idx"] != keep_policy_idx], reverse=True)
        for ridx in remove_indices:
            policy["grants"].pop(ridx)

        if mode == "m":
            return [
                f"dedup-service: merged {len(entries)} definition grants for '{svc}' into one (kept policy index {keep_policy_idx})"
            ]

        return [
            f"dedup-service: kept definition grant {keep_policy_idx} for '{svc}', removed {len(entries) - 1} duplicate(s)"
        ]


def apply_policy_fixes(policy: Dict[str, Any], owner_email: str, issues: List[Issue]) -> List[str]:
    notes: List[str] = []
    ensure_policy_shape(policy)

    for iss in issues:
        if not iss.fixable or not iss.data:
            continue

        if iss.kind == "missing-grant-tagowner":
            tag = iss.data["tag"]
            if tag not in policy["tagOwners"]:
                policy["tagOwners"][tag] = [owner_email]
                notes.append(f"fix: added tagOwner for {tag}")

        if iss.kind == "duplicate-service-definition-grants":
            service = iss.data.get("service") if iss.data else None
            if not service:
                continue
            notes.extend(dedup_service_definition_grants_prompt(policy, service))

        if iss.kind == "missing-grant":
            src = iss.data["src"]
            dst = iss.data["dst"]
            ip = iss.data["ip"]
            upsert_grant(policy, src=src, dst=dst, ip=ip)
            notes.append(f"fix: upserted grant {src} -> {dst} ({ip})")

    return notes


def collect_devname_tag_issues(policy: Dict[str, Any], tailnet: str, api_key: str) -> List[Issue]:
    ensure_policy_shape(policy)
    issues: List[Issue] = []
    devname_tags = list_devname_tags(policy)
    if not devname_tags:
        return issues

    devices = api_list_devices(tailnet, api_key)

    for dt in devname_tags:
        v = tag_value(dt)                 # devname-xyz
        devname = v[len("devname-"):]     # xyz

        matches = find_devices_by_ident(devices, devname)
        if not matches:
            issues.append(Issue(
                kind="devname-no-device-match",
                msg=f"Devname tag {dt} has no matching device named '{devname}'.",
                fixable=False,
                data={"tag": dt, "devname": devname},
            ))
            continue

        if len(matches) > 1:
            ids = [str(m.get("id")) for m in matches]
            issues.append(Issue(
                kind="devname-ambiguous-device-match",
                msg=f"Devname tag {dt} matches multiple devices for '{devname}': ids={ids}.",
                fixable=False,
                data={"tag": dt, "devname": devname, "ids": ids},
            ))
            continue

        d = matches[0]
        dev_id = str(d.get("id", "")).strip()
        if not dev_id:
            issues.append(Issue(
                kind="devname-device-missing-id",
                msg=f"Device matched for {dt} but has no id field; cannot tag it.",
                fixable=False,
                data={"tag": dt, "devname": devname},
            ))
            continue

        current = merge_tag_list(d.get("tags", []))
        if dt not in current:
            display = d.get("name") or d.get("hostname") or devname
            issues.append(Issue(
                kind="devname-tag-missing-on-device",
                msg=f"Device '{display}' (id {dev_id}) is missing tag {dt}.",
                fixable=True,
                data={"device_id": dev_id, "tag": dt, "display": display},
            ))

    return issues


def apply_devname_tag_fixes(dev_issues: List[Issue], tailnet: str, api_key: str) -> List[str]:
    notes: List[str] = []
    if not dev_issues:
        return notes

    devices = api_list_devices(tailnet, api_key)
    by_id: Dict[str, Dict[str, Any]] = {}
    for d in devices:
        did = str(d.get("id", "")).strip()
        if did:
            by_id[did] = d

    for iss in dev_issues:
        if not iss.fixable or not iss.data:
            continue
        if iss.kind != "devname-tag-missing-on-device":
            continue

        dev_id = iss.data["device_id"]
        tag = iss.data["tag"]
        display = iss.data.get("display", dev_id)

        d = by_id.get(dev_id)
        if not d:
            notes.append(f"fix-devnames: device id {dev_id} vanished between checks; skipped")
            continue

        current = merge_tag_list(d.get("tags", []))
        if tag in current:
            continue
        new_tags = sorted(set(current + [tag]))
        api_set_device_tags(dev_id, api_key, new_tags)
        notes.append(f"fix-devnames: applied {tag} to device '{display}' (id {dev_id})")

    return notes


# -----------------------------
# File I/O + output naming
# -----------------------------
def read_policy_file(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json5.loads(f.read())
    except FileNotFoundError:
        die(f"Input file not found: {path}")
    except Exception as e:
        die(f"Failed to parse input policy {path!r}: {e}")


def write_policy_file(path: str, policy: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(policy, indent=2))
        f.write("\n")


def write_pair(out_dir: str, basename: str, stamp: Optional[str], before: Dict[str, Any], after: Dict[str, Any]) -> Tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    if stamp:
        in_name = f"{basename}-{stamp}-in.json"
        out_name = f"{basename}-{stamp}-out.json"
    else:
        in_name = f"{basename}-in.json"
        out_name = f"{basename}-out.json"
    in_path = os.path.join(out_dir, in_name)
    out_path = os.path.join(out_dir, out_name)
    write_policy_file(in_path, before)
    write_policy_file(out_path, after)
    return in_path, out_path


def resolve_out_target(out_arg: str) -> Tuple[str, str]:
    out_arg = out_arg.strip()
    if out_arg.lower().endswith((".json", ".json5")):
        out_dir = os.path.dirname(out_arg) or "."
        base = os.path.splitext(os.path.basename(out_arg))[0]
        return out_dir, base
    return out_arg, DEFAULT_OUT_BASENAME


# -----------------------------
# CLI
# -----------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=True)

    # Input
    p.add_argument("--in", dest="infile", help="Read policy from a local file (JSON5/HuJSON ok).")
    p.add_argument("--pull", action="store_true", help="Pull current policy from your tailnet via API.")

    # Output
    p.add_argument("--out", dest="outdir", help="Write a pair of files (pre/post patch) to this directory or base file.")
    p.add_argument("--stamp", action="store_true", help="Use timestamped filenames for the --out pair.")
    p.add_argument("--push", action="store_true", help="Push updated policy to your tailnet via API (requires clean validation).")

    # Auth/config
    p.add_argument("--tailnet", default=cfg_get("TAILSCALE_TAILNET", DEFAULT_TAILNET), help="Tailnet name. Default is '-'.")
    p.add_argument("--api-key", default=cfg_get("TAILSCALE_API_KEY", DEFAULT_API_KEY), help="API key.")
    p.add_argument("--owner", default=cfg_get("TAILSCALE_OWNER_EMAIL", DEFAULT_OWNER_EMAIL), help="Owner email for tagOwners.")

    # Policy toggles
    p.add_argument(
        "--allow-all",
        dest="allow_all",
        choices=("yes", "no"),
        default=None,
        help="If 'yes', ensure an allow-all grant is present at the top of grants. If 'no', remove it. Omitted = no change.",
    )

    # Validation / fixing
    p.add_argument("--validate", action="store_true", help="Run validation checks (read-only). (Also runs by default.)")
    p.add_argument("--fix", action="store_true", help="Apply fixes for fixable validation issues (policy/devices).")
    p.add_argument("--validate-remote", action="store_true", help="Call Tailscale API /acl/validate (read-only).")
    p.add_argument(
        "--grant-gc",
        action="store_true",
        help="Garbage-collect unused tag:grant-* tagOwners and their associated policy grants (requires API). Apply removals with --fix.",
    )
    p.add_argument(
        "--allow-owner-change",
        action="store_true",
        help="Allow removing/replacing existing owner-* tags on devices (dangerous; requires --fix).",
    )

    # Devname tooling
    p.add_argument(
        "--gen-devname-tags",
        action="store_true",
        help="Generate expected tag:devname-* tagOwners entries from admin-console device names. Read-only unless combined with --fix.",
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("--autotag-devnames", dest="autotag_devnames", action="store_true", help="Check devices for missing devname tags; apply during --fix.")
    g.add_argument("--no-autotag-devnames", dest="autotag_devnames", action="store_false", help="Disable devname device-tag checks/fixes.")
    p.set_defaults(autotag_devnames=False)

    # Operations: repeatable
    p.add_argument(
        "--add",
        action="append",
        nargs="+",
        metavar=("KIND", "..."),
        help=(
            "Add: base <tags...> | service <name=ports> [name=ports ...] | "
            "grant <host=client:svc,svc> [more...] | tag <device=tags_csv> [more...] "
            "(device tagging applies only with --fix; otherwise it dry-runs)"
        ),
    )
    p.add_argument(
        "--rm",
        action="append",
        nargs="+",
        metavar=("KIND", "..."),
        help=(
            "Remove: base <tags...> | service <name> [name ...] | "
            "grant <host=client:svc,svc> [more...] | tag <device=tags_csv> [more...] "
            "(device tagging applies only with --fix; otherwise it dry-runs)"
        ),
    )

    return p


def require_api_args(tailnet: str, api_key: str) -> None:
    if not tailnet:
        die("Missing tailnet. Provide --tailnet, env TAILSCALE_TAILNET, or set DEFAULT_TAILNET.")
    if not api_key:
        die("Missing API key. Provide --api-key, env TAILSCALE_API_KEY, or set DEFAULT_API_KEY.")


def require_owner_email(owner: str) -> None:
    if not owner or not owner.strip():
        die(
            "Owner email is required for any operation that writes tagOwners.\n"
            "Set TAILSCALE_OWNER_EMAIL in ~/.config/mech-goodies/tailscale.env, export it, or pass --owner."
        )


def main() -> None:
    args = build_parser().parse_args()

    if not args.infile and not args.pull:
        die("You must provide --in FILE or --pull for input.")

    add_ops = args.add or []
    rm_ops = args.rm or []

    ops_need_api = any(op and op[0].lower() in ("tag", "grant") for op in (add_ops + rm_ops))
    needs_api = bool(
        args.pull
        or args.push
        or args.validate_remote
        or args.autotag_devnames
        or args.gen_devname_tags
        or args.grant_gc
        or ops_need_api
    )
    if needs_api:
        require_api_args(args.tailnet, args.api_key)

    # Load policy
    if args.pull:
        policy_before = api_pull_policy(args.tailnet, args.api_key)
    else:
        policy_before = read_policy_file(args.infile)

    ensure_policy_shape(policy_before)
    policy_after = copy.deepcopy(policy_before)

    # Pending host device tag changes from --add/--rm grant (applied only during --fix)
    pending_host_changes: Dict[str, PendingHostTagChange] = {}
    # Grant tags created in this run (protect from GC until we've had a chance to apply them)
    grant_gc_protect: set[str] = set()

    def get_or_make_pending(host_ident: str) -> PendingHostTagChange:
        if host_ident not in pending_host_changes:
            pending_host_changes[host_ident] = PendingHostTagChange(host_ident=host_ident, add_tags=[], remove_tags=[])
        return pending_host_changes[host_ident]

    # Apply ops (policy mutations; device tag ops apply only with --fix)
    for op in add_ops:
        kind = op[0].lower()
        if kind == "base":
            require_owner_email(args.owner)
            add_base(policy_after, args.owner, op[1:])
        elif kind == "service":
            require_owner_email(args.owner)
            if len(op) < 2:
                die("--add service requires: --add service <name=ports> [name=ports ...]")
            for svc_name, ports_spec in parse_service_specs(op[1:]):
                add_service(policy_after, args.owner, svc_name, ports_spec)
        elif kind == "grant":
            # policy side is always updated; device tagging happens only with --fix
            require_owner_email(args.owner)
            if len(op) < 2:
                die("--add grant requires: --add grant <host=client:svc,svc> [more...]")
            for host, client_tag, svcs in parse_grant_specs(op[1:]):
                for s in svcs:
                    gt = ensure_grant_tag_and_rule(policy_after, args.owner, client_tag, s)
                    pend = get_or_make_pending(host)
                    pend.add_tags.append(gt)
                    grant_gc_protect.add(gt)
        elif kind == "tag":
            require_owner_email(args.owner)
            if len(op) < 2:
                die("--add tag requires: --add tag <device=tags_csv> [more...]")
            for dev_ident, tags_csv in parse_device_tag_specs(op[1:]):
                add_or_rm_device_tags(
                    policy_after,
                    args.owner,
                    tailnet=args.tailnet,
                    api_key=args.api_key,
                    device_ident=dev_ident,
                    tags_csv=tags_csv,
                    remove=False,
                    allow_owner_change=args.allow_owner_change,
                    fix_enabled=args.fix,
                )
        else:
            die(f"Unknown --add kind: {kind!r}")

    for op in rm_ops:
        kind = op[0].lower()
        if kind == "base":
            rm_base(policy_after, op[1:])
        elif kind == "service":
            if len(op) < 2:
                die("--rm service requires: --rm service <name> [name ...]")
            for name in op[1:]:
                rm_service(policy_after, name)
        elif kind == "grant":
            if len(op) < 2:
                die("--rm grant requires: --rm grant <host=client:svc,svc> [more...]")
            for host, client_tag, svcs in parse_grant_specs(op[1:]):
                # remove host tag(s); policy cleanup is intentionally conservative
                for s in svcs:
                    _ = service_ports_or_die(policy_after, s)
                    client_val = tag_value(client_tag)
                    gt = grant_tag_for(s, client_val)
                    pend = get_or_make_pending(host)
                    pend.remove_tags.append(gt)
        elif kind == "tag":
            require_owner_email(args.owner)
            if len(op) < 2:
                die("--rm tag requires: --rm tag <device=tags_csv> [more...]")
            for dev_ident, tags_csv in parse_device_tag_specs(op[1:]):
                add_or_rm_device_tags(
                    policy_after,
                    args.owner,
                    tailnet=args.tailnet,
                    api_key=args.api_key,
                    device_ident=dev_ident,
                    tags_csv=tags_csv,
                    remove=True,
                    allow_owner_change=args.allow_owner_change,
                    fix_enabled=args.fix,
                )
        else:
            die(f"Unknown --rm kind: {kind!r}")

    # Optional: enforce/strip allow-all grant
    allow_all_notes = apply_allow_all_setting(policy_after, args.allow_all)
    if args.allow_all is not None and allow_all_notes:
        print(f"allow-all: {', '.join(allow_all_notes)}")

    # Optional: devname tagOwners generation checks
    desired_devname_tags: List[str] = []
    gen_notes: List[str] = []
    gen_issues: List[Issue] = []

    if args.gen_devname_tags:
        devices_cache = api_list_devices(args.tailnet, args.api_key)
        desired_devname_tags, gen_notes = desired_devname_tags_from_devices(devices_cache)
        gen_issues = collect_missing_devname_tagowners(policy_after, desired_devname_tags)

    # Validation (read-only checks)
    policy_issues = collect_policy_issues(policy_after)
    policy_issues.extend(gen_issues)

    dev_issues: List[Issue] = []
    if args.autotag_devnames:
        dev_issues = collect_devname_tag_issues(policy_after, args.tailnet, args.api_key)

    fix_notes: List[str] = []
    pushed_policy_early = False
    grant_gc_notes: List[str] = []

    # Fix (mutations) if requested
    if args.fix:
        # Any fixes that write tagOwners require owner email
        owner_needed = bool(gen_issues) or any(
            i.fixable and i.kind in ("missing-grant-tagowner", "missing-devname-tagowner") for i in policy_issues
        )
        if owner_needed:
            require_owner_email(args.owner)

        # 1) Policy-side fixes first
        if args.gen_devname_tags and gen_issues:
            fix_notes.extend(apply_missing_devname_tagowners(policy_after, args.owner, gen_issues))

        if policy_issues:
            fix_notes.extend(apply_policy_fixes(policy_after, args.owner, policy_issues))

        # Re-collect after policy fixes (before device operations)
        gen_issues = collect_missing_devname_tagowners(policy_after, desired_devname_tags) if args.gen_devname_tags else []
        policy_issues = collect_policy_issues(policy_after) + gen_issues

        # 2) Device-side fixes: devname autotag
        if args.autotag_devnames:
            dev_issues = collect_devname_tag_issues(policy_after, args.tailnet, args.api_key)

        # 3) Device-side changes for grants (pending host tagging)
        pending_changes_list = list(pending_host_changes.values())
        pending_add_tags = sorted(set(t for ch in pending_changes_list for t in ch.add_tags))

        # If we need to add tags to devices, the remote policy must already know those tags.
        # We'll push policy early ONLY if:
        #   - user requested --push (so we are allowed to write),
        #   - policy issues are clean (so we won't push broken policy),
        #   - and the tags are missing remotely.
        if (args.autotag_devnames and any(i.kind == "devname-tag-missing-on-device" for i in dev_issues)) or pending_add_tags:
            tags_to_apply = set(pending_add_tags)
            if args.autotag_devnames:
                for i in dev_issues:
                    if i.kind == "devname-tag-missing-on-device" and i.data and "tag" in i.data:
                        tags_to_apply.add(normalize_tag_selector(i.data["tag"]))

            if tags_to_apply:
                remote_policy = api_pull_policy(args.tailnet, args.api_key)
                remote_tagowners = set((remote_policy.get("tagOwners") or {}).keys())
                missing_remote = sorted(t for t in tags_to_apply if t not in remote_tagowners)

                if missing_remote:
                    if not args.push:
                        fix_notes.append(
                            f"fix-note: need policy pushed before device tagging (missing remote tagOwners for {missing_remote}); "
                            f"skipping device tagging because --push was not set"
                        )
                        # If we can't push, don't attempt device mutations
                        dev_issues = []
                        pending_host_changes = {}
                    else:
                        if policy_issues:
                            die(
                                "Refusing to push policy early for device tagging because policy validation issues remain. "
                                "Fix policy issues first, then re-run with --fix --push."
                            )
                        api_validate_policy(args.tailnet, args.api_key, policy_after)
                        api_push_policy(args.tailnet, args.api_key, policy_after)
                        pushed_policy_early = True
                        fix_notes.append(f"fix-note: pushed policy early to permit device tagging for tags: {missing_remote}")

        # Apply grant host tag changes (if still present)
        if pending_host_changes:
            fix_notes.extend(apply_pending_host_tag_changes(list(pending_host_changes.values()), args.tailnet, args.api_key))

        # Apply devname tagging fixes (if enabled)
        if args.autotag_devnames and dev_issues:
            fix_notes.extend(apply_devname_tag_fixes(dev_issues, args.tailnet, args.api_key))

        # 4) Re-run checks after fixing
        gen_issues = collect_missing_devname_tagowners(policy_after, desired_devname_tags) if args.gen_devname_tags else []
        policy_issues = collect_policy_issues(policy_after) + gen_issues
        dev_issues = collect_devname_tag_issues(policy_after, args.tailnet, args.api_key) if args.autotag_devnames else []

    # Optional: grant GC (not part of validation)
    if args.grant_gc:
        gc_issues = collect_unused_grant_tag_issues(policy_after, args.tailnet, args.api_key)
        # Protect tags created in this run (they may not be applied to hosts yet)
        gc_issues = [i for i in gc_issues if i.data and normalize_tag_selector(i.data.get("tag", "")) not in grant_gc_protect]
        if gc_issues:
            if args.fix:
                grant_gc_notes.extend(apply_grant_gc_fixes(policy_after, gc_issues))
            else:
                print("grant-gc findings (run with --fix to apply removals):")
                for iss in gc_issues:
                    print(f"  - {iss.msg}")

    # Optional: API-side validate without pushing
    if args.validate_remote:
        api_validate_policy(args.tailnet, args.api_key, policy_after)

    # Output pair (default to ~/.config/.../logs, timestamped)
    stamp = utc_stamp()
    want_pair = bool(args.outdir) or WRITE_TIMESTAMPED_PAIR_BY_DEFAULT
    if want_pair:
        out_dir, base = resolve_out_target(args.outdir or DEFAULT_LOG_DIR)
        use_stamp = args.stamp or (args.outdir is None)
        in_path, out_path = write_pair(
            out_dir=out_dir,
            basename=base,
            stamp=stamp if use_stamp else None,
            before=policy_before,
            after=policy_after,
        )
        print(f"Wrote policy pair:\n  {in_path}\n  {out_path}")

    all_issues = policy_issues + dev_issues

    if args.gen_devname_tags:
        print(f"gen-devname-tags: desired={len(desired_devname_tags)} missing-tagOwners={len(gen_issues)}")
        for n in gen_notes:
            print(f"  - {n}")

    if args.autotag_devnames:
        devname_tags_present = len(list_devname_tags(policy_after))
        missing_on_device = len([i for i in dev_issues if i.kind == "devname-tag-missing-on-device"])
        print(f"autotag-devnames: checked {devname_tags_present} devname tags; missing-on-device={missing_on_device}")

    if all_issues:
        print("\nValidation issues:")
        for iss in all_issues:
            flag = "fixable" if iss.fixable else "not-fixable"
            print(f"  - [{iss.kind}/{flag}] {iss.msg}")
    else:
        print("\nValidation: OK (no issues detected).")

    if fix_notes or grant_gc_notes:
        print("\nFix notes:")
        for n in fix_notes:
            print(f"  - {n}")
        for n in grant_gc_notes:
            print(f"  - {n}")

    # Push (only if clean). If we pushed early, only push again if policy differs (we don't track diffs; keep simple).
    if args.push:
        if all_issues:
            die("Refusing to --push: validation issues remain. Re-run with --fix (and/or fix manually).", code=3)
        if not pushed_policy_early:
            api_validate_policy(args.tailnet, args.api_key, policy_after)
            api_push_policy(args.tailnet, args.api_key, policy_after)
            print("Pushed policy successfully.")
        else:
            print("Policy already pushed earlier during --fix to permit device tagging; no further policy push needed.")

    # Exit code: nonzero if issues remain
    if all_issues:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
