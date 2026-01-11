#!/usr/bin/env python3
"""
tailscale.py (Tailscale policy + tagging helper)

What it does:
- --pull: fetch current tailnet ACL policy JSON from the Tailscale API
- --in: read a local policy file (JSON/JSON5/HuJSON-ish via json5)
- --out: write a *pair* of files (pre/post) to disk
- --validate: run read-only checks (default behavior anyway)
- --fix: apply fixes (policy edits and/or device tag edits), then re-validate
- --validate-remote: call Tailscale /acl/validate (read-only)
- --push: push policy back to the tailnet (only if validation is clean)
- --allow-all=(yes,no): yes ensures an allow-all grant exists at the top of "grants";
  no ensures there isn't. Omitted = no change.

Adding services:
- --add service <name=ports> [name=ports ...]
  Example:
    --add service sonarr=8989 radarr=7878 jellyfin=8096,8920

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

Devname workflow:
- --gen-devname-tags:
    - validate: detect missing tagOwners entries for tag:devname-<device>
    - fix: add missing tagOwners entries for those devname tags
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
  TAILSCALE_OWNER_EMAIL=me@example.com

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

import requests
import json5

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

BASE_PREFIXES = ("owner-", "devrole-", "ownerdept-", "devname-")
SERVICE_TAG_HEAD = "service-"  # tag value starts with "service-"


# -----------------------------
# Models
# -----------------------------
@dataclass
class Issue:
    kind: str
    msg: str
    fixable: bool = True
    data: Optional[dict] = None


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

ALLOW_ALL_GRANT = {"src": ["*"], "dst": ["*"], "ip": ["*"]}


def is_allow_all_grant(g: Any) -> bool:
    """
    Detect the canonical allow-all grant:
      {"src":["*"],"dst":["*"],"ip":["*"]}
    We intentionally ignore ordering in the dict and tolerate extra keys only if they are empty/absent.
    """
    if not isinstance(g, dict):
        return False
    if g.get("src") != ["*"] or g.get("dst") != ["*"] or g.get("ip") != ["*"]:
        return False

    # If someone made a "mostly allow all but with app/via/posture", don't treat it as the canonical allow-all.
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
    Returns human-friendly notes about what changed.
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

def parse_service_specs(tokens: Sequence[str]) -> List[Tuple[str, str]]:
    """
    Parse tokens like:
      ["sonarr=8989", "radarr=7878", "jellyfin=8096,8920", "foo=8000-8100"]
    Returns list of (service, ports_spec).
    """
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


def die(msg: str, code: int = 2) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def normalize_tag_selector(tag: str) -> str:
    """
    Accepts:
      owner-mschuett
      tag:owner-mschuett
    Returns:
      tag:owner-mschuett (lowercased)
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
    """tag:owner-mschuett -> owner-mschuett"""
    ts = normalize_tag_selector(tag_selector)
    return ts[4:]


def is_base_tag_selector(tag_selector: str) -> bool:
    v = tag_value(tag_selector)
    return any(v.startswith(p) for p in BASE_PREFIXES)


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
    Port ranges accept '-' or ':' in input (':' normalized to '-').
    Bare ports/ranges default to BOTH tcp+udp (least-privilege; avoids the implicit ICMP that "<port>" would allow).
    """
    raw = ports_spec.strip()
    if not raw:
        die("Ports spec is empty.")

    parts = [p.strip() for p in raw.split(",") if p.strip()]
    out: List[str] = []
    seen: set[str] = set()

    def emit(s: str) -> None:
        if s not in seen:
            out.append(s)
            seen.add(s)

    def validate_port(n: int) -> None:
        if not (1 <= n <= 65535):
            die(f"Port out of range: {n}")

    for tok in parts:
        # Optional suffix: /tcp or /udp (we only support these as requested)
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

        # Allow direct capability selectors (pass-through), e.g. tcp:443, udp:53, icmp:*, tcp:80-443
        # (If user writes these, they must NOT also use /tcp or /udp.)
        mcap = re.fullmatch(r"([a-z0-9]+):(\*|\d{1,5}|\d{1,5}-\d{1,5})", tok.lower())
        if mcap:
            if proto_suffix is not None:
                die(f"Do not combine proto selectors like {tok!r} with /tcp or /udp.")
            emit(tok.lower())
            continue

        # Allow "*" optionally scoped by /tcp or /udp
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

        # Parse single port
        if re.fullmatch(r"\d{1,5}", tok):
            port = int(tok)
            validate_port(port)
            if proto_suffix is None:
                emit(f"tcp:{port}")
                emit(f"udp:{port}")
            else:
                emit(f"{proto_suffix}:{port}")
            continue

        # Parse port range
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

    return out



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
    src_s = normalize_tag_selector(src)
    dst_s = normalize_tag_selector(dst)
    desired = {"src": [src_s], "dst": [dst_s], "ip": ip}

    grants: List[Dict[str, Any]] = policy["grants"]
    for g in grants:
        if g.get("src") == [src_s] and g.get("dst") == [dst_s]:
            g["ip"] = ip
            return
    grants.append(desired)


def grant_exists(policy: Dict[str, Any], src: str, dst: str, ip: Optional[List[str]] = None) -> bool:
    ensure_policy_shape(policy)
    src_s = normalize_tag_selector(src)
    dst_s = normalize_tag_selector(dst)
    for g in policy["grants"]:
        if g.get("src") == [src_s] and g.get("dst") == [dst_s]:
            if ip is None:
                return True
            if isinstance(g.get("ip"), list) and list(g["ip"]) == list(ip):
                return True
    return False


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


def parse_service_tag(tag_selector: str) -> Optional[Tuple[str, str]]:
    """
    tag:service-<service>-<baseTagValue>
    Returns: (serviceName, baseTagValue) where baseTagValue has no "tag:" prefix.
    """
    ts = normalize_tag_selector(tag_selector)
    v = tag_value(ts)  # e.g. "service-jellyfin-owner-mschuett"
    if not v.startswith(SERVICE_TAG_HEAD):
        return None

    rest = v[len(SERVICE_TAG_HEAD):]  # "jellyfin-owner-mschuett"
    for base_prefix in BASE_PREFIXES:
        marker = "-" + base_prefix
        idx = rest.rfind(marker)
        if idx > 0:
            service = rest[:idx]
            base = rest[idx + 1:]
            return (service, base)
    return None


def list_services(policy: Dict[str, Any]) -> List[str]:
    ensure_policy_shape(policy)
    services = set()

    # Discover from tagOwners
    for t in policy["tagOwners"].keys():
        parsed = parse_service_tag(t)
        if parsed:
            services.add(parsed[0])

    # Discover from grants too
    for g in policy["grants"]:
        dsts = g.get("dst")
        if isinstance(dsts, list) and len(dsts) == 1 and isinstance(dsts[0], str):
            parsed = parse_service_tag(dsts[0])
            if parsed:
                services.add(parsed[0])

    return sorted(services)


def service_tag_for(service: str, base_tag_value: str) -> str:
    return normalize_tag_selector(f"service-{service}-{base_tag_value}")


def infer_service_ip_from_grants(policy: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Canonical ports per service are inferred from existing grants that target that service.
    """
    ensure_policy_shape(policy)
    service_ip: Dict[str, List[str]] = {}

    for g in policy["grants"]:
        dsts = g.get("dst", [])
        if not (isinstance(dsts, list) and dsts):
            continue
        dst0 = dsts[0]
        parsed = parse_service_tag(dst0)
        if not parsed:
            continue
        service, _base = parsed
        ip = g.get("ip", [])
        if isinstance(ip, list) and ip and service not in service_ip:
            service_ip[service] = list(ip)

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
    """
    Fields we allow matching against for user-provided device identifiers.
    We normalize by stripping the tailnet suffix when present.
    """
    fields: List[str] = []
    for k in ("name", "hostname", "hostName", "machineName", "dnsName"):
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            fields.append(strip_tsnet_tailnet_suffix(v.strip()))
    return fields


def find_devices_by_devname(devices: List[Dict[str, Any]], devname: str) -> List[Dict[str, Any]]:
    target = devname.strip().lower()
    if not target:
        return []

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
    return out


# -----------------------------
# Devname tag generation
# -----------------------------
def sanitize_for_tag_component(s: str) -> str:
    """
    Convert arbitrary device names into a safe tag component:
    - lowercase
    - non [a-z0-9] -> '-'
    - collapse '-' runs
    - strip leading/trailing '-'
    """
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-{2,}", "-", s)
    s = s.strip("-")
    return s or "unknown"


def devname_tag_for_device_name(name: str) -> str:
    comp = sanitize_for_tag_component(name)
    return normalize_tag_selector(f"devname-{comp}")


def desired_devname_tags_from_devices(devices: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """
    Returns:
      desired_tags: unique list of tag selectors (tag:devname-*)
      notes: collisions/skips
    """
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
# Ops: add/rm base/service/tag
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

    base_values = {tag_value(t) for t in norm}

    def is_service_for_removed_base(tag_sel: str) -> bool:
        parsed = parse_service_tag(tag_sel)
        return bool(parsed and parsed[1] in base_values)

    for t in list(policy.get("tagOwners", {}).keys()):
        if is_service_for_removed_base(t):
            policy["tagOwners"].pop(t, None)

    base_set = set(norm)
    kept = []
    for g in policy.get("grants", []):
        srcs = g.get("src", [])
        dsts = g.get("dst", [])

        if not isinstance(srcs, list) or not isinstance(dsts, list) or not srcs or not dsts:
            kept.append(g)
            continue

        if len(srcs) == 1 and srcs[0] in base_set:
            continue

        if len(dsts) == 1 and is_service_for_removed_base(dsts[0]):
            continue

        kept.append(g)
    policy["grants"] = kept


def add_service(policy: Dict[str, Any], owner_email: str, service: str, ports_spec: str) -> None:
    svc = service.strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9-]*", svc):
        die("Service name must be letters/digits/dashes, starting with a letter.")

    ip = parse_ports_spec(ports_spec)
    base_tags = list_base_tags(policy)
    if not base_tags:
        die("No base tags found in tagOwners. Add base tags first (--add base ...).")

    for bt in base_tags:
        bt_val = tag_value(bt)
        st = service_tag_for(svc, bt_val)
        set_tag_owner(policy, st, owner_email)
        upsert_grant(policy, src=bt, dst=st, ip=ip)


def rm_service(policy: Dict[str, Any], service: str) -> None:
    svc = service.strip().lower()
    if not svc:
        die("Service name is empty.")
    ensure_policy_shape(policy)

    to_remove = []
    for t in policy["tagOwners"].keys():
        parsed = parse_service_tag(t)
        if parsed and parsed[0] == svc:
            to_remove.append(t)
    for t in to_remove:
        policy["tagOwners"].pop(t, None)

    kept = []
    for g in policy["grants"]:
        dsts = g.get("dst", [])
        if isinstance(dsts, list) and len(dsts) == 1:
            parsed = parse_service_tag(dsts[0])
            if parsed and parsed[0] == svc:
                continue
        kept.append(g)
    policy["grants"] = kept


def add_or_rm_device_tags(
    policy: Dict[str, Any],
    owner_email: str,
    *,
    tailnet: str,
    api_key: str,
    device_ident: str,
    tags_csv: str,
    remove: bool,
) -> None:
    tags = parse_tags_csv(tags_csv)

    # Ensure tags exist in tagOwners so they can be applied.
    for t in tags:
        set_tag_owner(policy, t, owner_email)

    devices = api_list_devices(tailnet, api_key)

    matches = find_devices_by_devname(devices, device_ident)
    if not matches:
        die(f"No device found matching {device_ident!r}. Use an exact device name (or its prefix) or numeric id.")
    if len(matches) > 1:
        ids = ", ".join(str(m.get("id")) for m in matches)
        die(f"Device identifier matched multiple devices (ids: {ids}). Use a numeric id.")

    dev = matches[0]
    dev_id = str(dev.get("id", "")).strip()
    if not dev_id:
        die("Device record has no 'id' field; cannot tag.")

    current_norm = merge_tag_list(dev.get("tags", []))
    if remove:
        new_tags = [t for t in current_norm if t not in tags]
    else:
        new_tags = sorted(set(current_norm).union(tags))

    api_set_device_tags(dev_id, api_key, new_tags)


# -----------------------------
# Validation (read-only) + Fix
# -----------------------------
def collect_policy_issues(policy: Dict[str, Any]) -> List[Issue]:
    """
    Read-only: detect missing service tags/grants based on the existing service model.
    """
    ensure_policy_shape(policy)
    issues: List[Issue] = []

    base_tags = list_base_tags(policy)
    services = list_services(policy)
    service_ip = infer_service_ip_from_grants(policy)

    for s in services:
        if s not in service_ip:
            issues.append(Issue(
                kind="service-missing-ports",
                msg=f"Service '{s}' has no inferable canonical ports (no existing grants for it).",
                fixable=False,
                data={"service": s},
            ))

    for s in services:
        ip = service_ip.get(s)
        if not ip:
            continue

        for bt in base_tags:
            bt_val = tag_value(bt)
            st = service_tag_for(s, bt_val)

            if st not in policy["tagOwners"]:
                issues.append(Issue(
                    kind="missing-service-tag",
                    msg=f"Missing tagOwners entry for {st} (service '{s}' x base '{bt}').",
                    fixable=True,
                    data={"service": s, "base": bt, "service_tag": st, "ip": ip},
                ))

            if not grant_exists(policy, bt, st, ip=ip):
                issues.append(Issue(
                    kind="missing-grant",
                    msg=f"Missing grant {bt} -> {st} with ip={ip}.",
                    fixable=True,
                    data={"service": s, "base": bt, "service_tag": st, "ip": ip},
                ))

    return issues


def apply_policy_fixes(policy: Dict[str, Any], owner_email: str, issues: List[Issue]) -> List[str]:
    """
    Mutates policy to repair fixable issues only. Returns notes.
    """
    notes: List[str] = []
    ensure_policy_shape(policy)

    for iss in issues:
        if not iss.fixable or not iss.data:
            continue

        if iss.kind in ("missing-service-tag", "missing-grant"):
            st = iss.data["service_tag"]
            bt = iss.data["base"]
            ip = iss.data["ip"]

            if st not in policy["tagOwners"]:
                policy["tagOwners"][st] = [owner_email]
                notes.append(f"fix: added tagOwner for {st}")

            if not grant_exists(policy, bt, st, ip=ip):
                upsert_grant(policy, src=bt, dst=st, ip=ip)
                notes.append(f"fix: added grant {bt} -> {st} ({ip})")

    return notes


def collect_devname_tag_issues(policy: Dict[str, Any], tailnet: str, api_key: str) -> List[Issue]:
    """
    Read-only: for each devname tag in tagOwners, check if the matching device has that tag.
    """
    ensure_policy_shape(policy)
    issues: List[Issue] = []
    devname_tags = list_devname_tags(policy)
    if not devname_tags:
        return issues

    devices = api_list_devices(tailnet, api_key)

    for dt in devname_tags:
        v = tag_value(dt)                 # devname-xyz
        devname = v[len("devname-"):]     # xyz

        matches = find_devices_by_devname(devices, devname)
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
    """
    Mutates devices (API calls) to apply missing devname tags. Returns notes.
    """
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
    """
    If out_arg ends with .json/.json5 -> treat as a base filename:
      --out tailnet.json  => out_dir=".", base="tailnet"
      --out foo/bar.json  => out_dir="foo", base="bar"
    Else treat as directory:
      --out outdir        => out_dir="outdir", base=DEFAULT_OUT_BASENAME
    """
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

    # Validation / fixing
    p.add_argument("--validate", action="store_true", help="Run validation checks (read-only). (Also runs by default.)")
    p.add_argument("--fix", action="store_true", help="Apply fixes for fixable validation issues (policy/devices).")
    p.add_argument("--validate-remote", action="store_true", help="Call Tailscale API /acl/validate (read-only).")

    #Policy 
    p.add_argument(
    "--allow-all",
    dest="allow_all",
    choices=("yes", "no"),
    default=None,
    help="If 'yes', ensure an allow-all grant is present at the top of grants. If 'no', remove it. Omitted = no change.",)


    # Devname tooling
    p.add_argument(
        "--gen-devname-tags",
        action="store_true",
        help="Generate expected tag:devname-* tagOwners entries from admin-console device names. "
             "Read-only unless combined with --fix.",
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("--autotag-devnames", dest="autotag_devnames", action="store_true",
                   help="Check devices for missing devname tags; apply during --fix.")
    g.add_argument("--no-autotag-devnames", dest="autotag_devnames", action="store_false",
                   help="Disable devname device-tag checks/fixes.")
    p.set_defaults(autotag_devnames=False)

    # Operations: repeatable
    p.add_argument(
        "--add",
        action="append",
        nargs="+",
        metavar=("KIND", "..."),
        help="Add: base <tags...> | service <name=ports> [name=ports ...] | tag <device> <tags_csv> (device tagging requires --fix).",
    )
    p.add_argument(
        "--rm",
        action="append",
        nargs="+",
        metavar=("KIND", "..."),
        help="Remove: base <tags...> | service <name> | tag <device> <tags_csv> (device tagging requires --fix).",
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

    needs_api = bool(args.pull or args.push or args.validate_remote or args.autotag_devnames or args.gen_devname_tags)
    if needs_api:
        require_api_args(args.tailnet, args.api_key)

    # Load policy
    if args.pull:
        policy_before = api_pull_policy(args.tailnet, args.api_key)
    else:
        policy_before = read_policy_file(args.infile)

    ensure_policy_shape(policy_before)
    policy_after = copy.deepcopy(policy_before)

    # Apply ops (policy mutations; device tag ops require --fix)
    add_ops = args.add or []
    rm_ops = args.rm or []

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
        elif kind == "tag":
            if not args.fix:
                die("--add tag changes device state; run with --fix to allow it.")
            require_owner_email(args.owner)
            if len(op) != 3:
                die("--add tag requires: --add tag <device> <tags_csv>")
            add_or_rm_device_tags(
                policy_after,
                args.owner,
                tailnet=args.tailnet,
                api_key=args.api_key,
                device_ident=op[1],
                tags_csv=op[2],
                remove=False,
            )
        else:
            die(f"Unknown --add kind: {kind!r}")

    for op in rm_ops:
        kind = op[0].lower()
        if kind == "base":
            rm_base(policy_after, op[1:])
        elif kind == "service":
            if len(op) != 2:
                die("--rm service requires: --rm service <name>")
            rm_service(policy_after, op[1])
        elif kind == "tag":
            if not args.fix:
                die("--rm tag changes device state; run with --fix to allow it.")
            require_owner_email(args.owner)
            if len(op) != 3:
                die("--rm tag requires: --rm tag <device> <tags_csv>")
            add_or_rm_device_tags(
                policy_after,
                args.owner,
                tailnet=args.tailnet,
                api_key=args.api_key,
                device_ident=op[1],
                tags_csv=op[2],
                remove=True,
            )
        else:
            die(f"Unknown --rm kind: {kind!r}")
    # Optional: enforce/strip allow-all grant (policy edit)
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
    pushed_policy_early = False  # PATCH: if we must push tagOwners before tagging devices

    # Fix (mutations) if requested
    if args.fix:
        # Any fixes that write tagOwners require owner email
        if (args.gen_devname_tags and gen_issues) or any(i.kind in ("missing-service-tag", "missing-grant") for i in policy_issues):
            require_owner_email(args.owner)

        # 1) Policy-side fixes first (this can create devname tags)
        if args.gen_devname_tags and gen_issues:
            fix_notes.extend(apply_missing_devname_tagowners(policy_after, args.owner, gen_issues))

        if policy_issues:
            fix_notes.extend(apply_policy_fixes(policy_after, args.owner, policy_issues))

        # 2) Now that policy/tagOwners may have changed, re-collect dev issues
        if args.autotag_devnames:
            dev_issues = collect_devname_tag_issues(policy_after, args.tailnet, args.api_key)

            # PATCH: If we need to apply tags to devices, those tags must already exist
            # in the CURRENTLY APPLIED tailnet policy. If not, push policy first (if allowed).
            need_tags = sorted({
                iss.data["tag"]
                for iss in dev_issues
                if iss.kind == "devname-tag-missing-on-device" and iss.data and "tag" in iss.data
            })

            if need_tags:
                remote_policy = policy_before if args.pull else api_pull_policy(args.tailnet, args.api_key)
                remote_tagowners = remote_policy.get("tagOwners", {}) or {}

                missing_remote = [t for t in need_tags if t not in remote_tagowners]
                if missing_remote:
                    if not args.push:
                        fix_notes.append(
                            "fix-devnames: skipped device tagging because required devname tags are not yet present "
                            "in the active tailnet policy (run again with --push, or push policy first)."
                        )
                    else:
                        # Push policy FIRST so the device-tag API will permit those tags.
                        api_validate_policy(args.tailnet, args.api_key, policy_after)
                        api_push_policy(args.tailnet, args.api_key, policy_after)
                        pushed_policy_early = True
                        fix_notes.append(
                            f"fix-devnames: pushed policy early to permit device tagging (missing tags: {missing_remote})"
                        )

                # 3) Apply device tagging fixes (only if we didn't skip)
                if dev_issues and (not missing_remote or args.push):
                    fix_notes.extend(apply_devname_tag_fixes(dev_issues, args.tailnet, args.api_key))

        # 4) Re-run checks after fixing
        gen_issues = collect_missing_devname_tagowners(policy_after, desired_devname_tags) if args.gen_devname_tags else []
        policy_issues = collect_policy_issues(policy_after) + gen_issues
        dev_issues = collect_devname_tag_issues(policy_after, args.tailnet, args.api_key) if args.autotag_devnames else []

    # Optional: API-side validate without pushing
    if args.validate_remote:
        api_validate_policy(args.tailnet, args.api_key, policy_after)

    # Output pair
    stamp = utc_stamp()
    want_pair = bool(args.outdir) or WRITE_TIMESTAMPED_PAIR_BY_DEFAULT
    if want_pair:
        # Default output directory is ~/.config/mech-goodies/tailscale/logs/
        out_dir, base = resolve_out_target(args.outdir or DEFAULT_LOG_DIR)

        # If user didn't specify --out, default to timestamped to avoid overwrites
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

    if fix_notes:
        print("\nFix notes:")
        for n in fix_notes:
            print(f"  - {n}")

    # Push (only if clean)
    if args.push:
        if all_issues:
            die("Refusing to --push: validation issues remain. Re-run with --fix (and/or fix manually).", code=3)

        # PATCH: If we already pushed earlier (to permit device tagging), don't push again.
        if not pushed_policy_early:
            api_validate_policy(args.tailnet, args.api_key, policy_after)
            api_push_policy(args.tailnet, args.api_key, policy_after)
            print("Pushed policy successfully.")
        else:
            print("Policy was already pushed earlier (to permit device tagging).")

    # Exit code: nonzero if issues remain
    if all_issues:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
