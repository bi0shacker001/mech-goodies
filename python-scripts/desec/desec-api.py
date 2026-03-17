#!/usr/bin/env python3
"""
deSEC Token Manager — TUI for creating and managing API tokens with scoped policies.
Requires: pip install textual httpx

Config: ~/.config/mech-goodies/desec.env
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING
import httpx
try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _yaml = None  # type: ignore[assignment]
    _YAML_AVAILABLE = False
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.screen import Screen, ModalScreen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label,
    Select, Static, Switch, Checkbox, TextArea
)
from textual.reactive import reactive
from textual import on, work
from textual.worker import WorkerError

# ──────────────────────────────────────────────────────────────────────────────
# .env config management
# ──────────────────────────────────────────────────────────────────────────────

ENV_PATH = Path.home() / ".config" / "mech-goodies" / "desec.env"

# All vars the script uses, with metadata:
#   key        → env var name
#   default    → value written when commented out (empty string = blank placeholder)
#   secret     → True means it's written as a real value on first save, not commented
#   comment    → description line above the var in the file
ENV_SCHEMA: list[dict] = [
    {
        "key": "DESEC_TOKEN",
        "default": "",
        "secret": True,
        "comment": "deSEC master API token (must have perm_manage_tokens)",
    },
    {
        "key": "DESEC_API_BASE",
        "default": "https://desec.io/api/v1",
        "secret": False,
        "comment": "deSEC API base URL (change only for self-hosted instances)",
    },
]


def _parse_env_file(path: Path) -> dict[str, str | None]:
    """
    Parse a .env file, returning {KEY: value_or_None}.
    None = key present but commented out.
    Keys not in the file are absent from the result entirely.
    """
    result: dict[str, str | None] = {}
    if not path.exists():
        return result
    for line in path.read_text().splitlines():
        # commented-out var
        m = re.match(r"^#\s*([A-Z_][A-Z0-9_]*)=(.*)$", line)
        if m:
            result[m.group(1)] = None
            continue
        # active var
        m = re.match(r"^([A-Z_][A-Z0-9_]*)=(.*)$", line)
        if m:
            result[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    return result


def load_env() -> dict[str, str]:
    """Load active (non-commented) values from the env file."""
    parsed = _parse_env_file(ENV_PATH)
    return {k: v for k, v in parsed.items() if v is not None}


def save_env(updates: dict[str, str]) -> None:
    """
    Write or update the env file.
    - For keys in `updates`: write as active KEY=value
    - For schema keys missing entirely from the file: append as commented-out
    - Never removes existing lines or comments
    - Preserves existing file content and order
    """
    ENV_PATH.parent.mkdir(parents=True, exist_ok=True)

    existing_lines: list[str] = []
    if ENV_PATH.exists():
        existing_lines = ENV_PATH.read_text().splitlines()

    parsed = _parse_env_file(ENV_PATH)

    # Update or replace lines for keys in `updates`
    new_lines: list[str] = []
    replaced: set[str] = set()
    skip_next_if_comment: bool = False

    i = 0
    while i < len(existing_lines):
        line = existing_lines[i]
        matched_key: str | None = None

        # Active line?
        m = re.match(r"^([A-Z_][A-Z0-9_]*)=(.*)$", line)
        if m and m.group(1) in updates:
            matched_key = m.group(1)

        # Commented line?
        m2 = re.match(r"^#\s*([A-Z_][A-Z0-9_]*)=(.*)$", line)
        if m2 and m2.group(1) in updates:
            matched_key = m2.group(1)

        if matched_key:
            new_lines.append(f"{matched_key}={updates[matched_key]}")
            replaced.add(matched_key)
        else:
            new_lines.append(line)
        i += 1

    # Append any updated keys not yet in the file
    for key, value in updates.items():
        if key not in replaced:
            schema_entry = next((s for s in ENV_SCHEMA if s["key"] == key), None)
            if schema_entry:
                new_lines.append(f"\n# {schema_entry['comment']}")
            new_lines.append(f"{key}={value}")
            replaced.add(key)

    # Append schema keys that are entirely absent from the file (as commented-out)
    for entry in ENV_SCHEMA:
        key = entry["key"]
        if key not in parsed and key not in replaced:
            new_lines.append(f"\n# {entry['comment']}")
            new_lines.append(f"# {key}={entry['default']}")

    ENV_PATH.write_text("\n".join(new_lines) + "\n")


def ensure_env_complete() -> None:
    """
    Called on startup: if env file exists, ensure all schema keys are present
    (at least as commented-out stubs). If file doesn't exist, do nothing —
    we create it after first successful login.
    """
    if not ENV_PATH.exists():
        return
    parsed = _parse_env_file(ENV_PATH)
    missing = [e for e in ENV_SCHEMA if e["key"] not in parsed]
    if not missing:
        return
    # Append missing keys as commented stubs
    with ENV_PATH.open("a") as f:
        for entry in missing:
            f.write(f"\n# {entry['comment']}\n")
            f.write(f"# {entry['key']}={entry['default']}\n")


# ──────────────────────────────────────────────────────────────────────────────
# API helpers
# ──────────────────────────────────────────────────────────────────────────────

def get_api_base() -> str:
    return load_env().get("DESEC_API_BASE", "https://desec.io/api/v1").rstrip("/")


def api_headers(token: str) -> dict:
    return {"Authorization": f"Token {token}", "Content-Type": "application/json"}


def list_tokens(token: str) -> list:
    r = httpx.get(f"{get_api_base()}/auth/tokens/", headers=api_headers(token), timeout=10)
    r.raise_for_status()
    return r.json()


def create_token(token: str, name: str, perm_manage_tokens: bool,
                 perm_create_domain: bool, perm_delete_domain: bool,
                 allowed_subnets: list[str], max_unused_period: str | None,
                 auto_policy: bool) -> dict:
    payload: dict = {
        "name": name,
        "perm_manage_tokens": perm_manage_tokens,
        "perm_create_domain": perm_create_domain,
        "perm_delete_domain": perm_delete_domain,
        "auto_policy": auto_policy,
    }
    if allowed_subnets:
        payload["allowed_subnets"] = allowed_subnets
    if max_unused_period:
        payload["max_unused_period"] = max_unused_period
    r = httpx.post(f"{get_api_base()}/auth/tokens/", headers=api_headers(token),
                   json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


def delete_token(token: str, token_id: str) -> None:
    r = httpx.delete(f"{get_api_base()}/auth/tokens/{token_id}/",
                     headers=api_headers(token), timeout=10)
    r.raise_for_status()


def list_policies(token: str, token_id: str) -> list:
    r = httpx.get(f"{get_api_base()}/auth/tokens/{token_id}/policies/rrsets/",
                  headers=api_headers(token), timeout=10)
    r.raise_for_status()
    return r.json()


def create_policy(token: str, token_id: str, domain: str | None,
                  subname: str | None, rtype: str | None, perm_write: bool) -> dict:
    payload = {
        "domain": domain or None,
        "subname": subname or None,
        "type": rtype or None,
        "perm_write": perm_write,
    }
    r = httpx.post(f"{get_api_base()}/auth/tokens/{token_id}/policies/rrsets/",
                   headers=api_headers(token), json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


def delete_policy(token: str, token_id: str, policy_id: str) -> None:
    r = httpx.delete(
        f"{get_api_base()}/auth/tokens/{token_id}/policies/rrsets/{policy_id}/",
        headers=api_headers(token), timeout=10)
    r.raise_for_status()


def list_domains(token: str) -> list:
    r = httpx.get(f"{get_api_base()}/domains/", headers=api_headers(token), timeout=10)
    r.raise_for_status()
    return r.json()


def create_domain(token: str, name: str) -> dict:
    r = httpx.post(f"{get_api_base()}/domains/", headers=api_headers(token),
                   json={"name": name}, timeout=10)
    r.raise_for_status()
    return r.json()


def delete_domain(token: str, name: str) -> None:
    r = httpx.delete(f"{get_api_base()}/domains/{name}/",
                     headers=api_headers(token), timeout=10)
    r.raise_for_status()


def list_rrsets(token: str, domain: str) -> list:
    r = httpx.get(f"{get_api_base()}/domains/{domain}/rrsets/",
                  headers=api_headers(token), timeout=10)
    r.raise_for_status()
    return r.json()


def create_rrset(token: str, domain: str, subname: str, rtype: str,
                 ttl: int, records: list[str]) -> dict:
    payload = {"subname": subname, "type": rtype, "ttl": ttl, "records": records}
    r = httpx.post(f"{get_api_base()}/domains/{domain}/rrsets/",
                   headers=api_headers(token), json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


def update_rrset(token: str, domain: str, subname: str, rtype: str,
                 ttl: int, records: list[str]) -> dict:
    payload = {"ttl": ttl, "records": records}
    r = httpx.patch(f"{get_api_base()}/domains/{domain}/rrsets/{subname}/{rtype}/",
                    headers=api_headers(token), json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


def delete_rrset(token: str, domain: str, subname: str, rtype: str) -> None:
    r = httpx.delete(f"{get_api_base()}/domains/{domain}/rrsets/{subname}/{rtype}/",
                     headers=api_headers(token), timeout=10)
    r.raise_for_status()


def upsert_rrset(token: str, domain: str, subname: str, rtype: str,
                 ttl: int, records: list[str]) -> dict:
    """Create an RRset, falling back to update if it already exists."""
    try:
        return create_rrset(token, domain, subname, rtype, ttl, records)
    except httpx.HTTPStatusError as e:
        if e.response.status_code in (400, 409):
            return update_rrset(token, domain, subname, rtype, ttl, records)
        raise


def _acme_subname(subname: str) -> str:
    """Return the _acme-challenge subname label for a ACME DNS-01 challenge."""
    return f"_acme-challenge.{subname}" if subname else "_acme-challenge"


def provision_ddns_token(
    master_token: str,
    name: str,
    domain: str,
    subname: str,
    ipv4: str | None,
    ipv6: str | None,
    ttl: int = 3600,
) -> dict:
    """
    DDNS provisioning wizard:
      1. Optionally set initial A / AAAA records (using master_token).
      2. Create a token scoped to write A + AAAA records for that domain+subname only.
    The generated token cannot touch any other record type, domain, or subdomain.
    """
    if ipv4:
        upsert_rrset(master_token, domain, subname, "A", ttl, [ipv4])
    if ipv6:
        upsert_rrset(master_token, domain, subname, "AAAA", ttl, [ipv6])
    tok = create_token(
        master_token, name,
        perm_manage_tokens=False,
        perm_create_domain=False,
        perm_delete_domain=False,
        allowed_subnets=[],
        max_unused_period=None,
        auto_policy=False,
    )
    tok_id = tok["id"]
    # deSEC requires a default (catch-all) policy first before any scoped ones.
    create_policy(master_token, tok_id, None, None, None, perm_write=False)
    # Always grant both A and AAAA regardless of which initial values were given,
    # so the client can later update whichever address family changes.
    create_policy(master_token, tok_id, domain, subname or None, "A",    perm_write=True)
    create_policy(master_token, tok_id, domain, subname or None, "AAAA", perm_write=True)
    return tok


def provision_cert_token(
    master_token: str,
    name: str,
    domain: str,
    subname: str,
    ipv4: str | None,
    ipv6: str | None,
    cname: str | None,
    ttl: int = 3600,
) -> dict:
    """
    Single-domain cert provisioning wizard:
      1. Optionally set initial address / CNAME records using master_token
         (the address records are NOT granted to the generated token).
      2. Create a token scoped only to TXT writes at _acme-challenge.<hostname>,
         suitable for DNS-01 ACME certificate challenges.
    """
    if cname:
        upsert_rrset(master_token, domain, subname, "CNAME", ttl, [cname])
    else:
        if ipv4:
            upsert_rrset(master_token, domain, subname, "A", ttl, [ipv4])
        if ipv6:
            upsert_rrset(master_token, domain, subname, "AAAA", ttl, [ipv6])
    tok = create_token(
        master_token, name,
        perm_manage_tokens=False,
        perm_create_domain=False,
        perm_delete_domain=False,
        allowed_subnets=[],
        max_unused_period=None,
        auto_policy=False,
    )
    tok_id = tok["id"]
    # deSEC requires a default (catch-all) policy first before any scoped ones.
    create_policy(master_token, tok_id, None, None, None, perm_write=False)
    create_policy(master_token, tok_id, domain, _acme_subname(subname), "TXT", perm_write=True)
    return tok


def provision_cert_multi_token(
    master_token: str,
    name: str,
    entries: list[tuple[str, str]],
) -> dict:
    """
    Multi-domain cert provisioning wizard:
      Creates a token scoped to TXT writes at _acme-challenge.<hostname> for each
      (domain, subname) entry.  No address records are touched or granted — least privilege.
    """
    tok = create_token(
        master_token, name,
        perm_manage_tokens=False,
        perm_create_domain=False,
        perm_delete_domain=False,
        allowed_subnets=[],
        max_unused_period=None,
        auto_policy=False,
    )
    tok_id = tok["id"]
    # deSEC requires a default (catch-all) policy first before any scoped ones.
    create_policy(master_token, tok_id, None, None, None, perm_write=False)
    for domain, subname in entries:
        create_policy(master_token, tok_id, domain, _acme_subname(subname), "TXT", perm_write=True)
    return tok


# ──────────────────────────────────────────────────────────────────────────────
# Modals
# ──────────────────────────────────────────────────────────────────────────────

class MessageModal(ModalScreen):
    """Simple info / error popup."""

    BINDINGS = [Binding("escape,enter,space", "dismiss", "Close")]

    def __init__(self, title: str, message: str, is_error: bool = False):
        super().__init__()
        self._title = title
        self._message = message
        self._is_error = is_error

    def compose(self) -> ComposeResult:
        colour = "red" if self._is_error else "green"
        with Container(id="modal-box"):
            yield Label(f"[bold {colour}]{self._title}[/]", id="modal-title")
            yield Static(self._message, id="modal-body")
            yield Button("OK", id="ok-btn", variant="primary")

    @on(Button.Pressed, "#ok-btn")
    def close(self) -> None:
        self.dismiss()


class ConfirmModal(ModalScreen[bool]):
    """Yes/No confirmation."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, message: str):
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Container(id="modal-box"):
            yield Label("[bold yellow]Confirm[/]", id="modal-title")
            yield Static(self._message, id="modal-body")
            with Horizontal(id="modal-buttons"):
                yield Button("Yes", id="yes-btn", variant="error")
                yield Button("No", id="no-btn", variant="primary")

    @on(Button.Pressed, "#yes-btn")
    def yes(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#no-btn")
    def no(self) -> None:
        self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)


class NewSecretModal(ModalScreen):
    """Displays the one-time token secret."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, token_name: str, secret: str):
        super().__init__()
        self._name = token_name
        self._secret = secret

    def compose(self) -> ComposeResult:
        with Container(id="modal-box"):
            yield Label("[bold green]Token created![/]", id="modal-title")
            yield Static(
                f"[bold]Name:[/] {self._name}\n\n"
                f"[bold red]Secret (shown once — copy it now):[/]\n\n"
                f"[bold yellow]{self._secret}[/]",
                id="modal-body",
            )
            yield Button("I've copied it", id="ok-btn", variant="primary")

    @on(Button.Pressed, "#ok-btn")
    def close(self) -> None:
        self.dismiss()


class CreateTokenModal(ModalScreen[dict | None]):
    """Form to create a new token."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Container(id="modal-box", classes="wide"):
            yield Label("[bold cyan]Create New Token[/]", id="modal-title")
            with ScrollableContainer():
                yield Label("Token name")
                yield Input(placeholder="e.g. certbot-example.com", id="name-input")
                yield Label("Allowed subnets (comma-separated, leave blank for any)")
                yield Input(placeholder="e.g. 203.0.113.0/24, 2001:db8::/32", id="subnets-input")
                yield Label("Max unused period (ISO 8601 duration, e.g. P90D — blank = none)")
                yield Input(placeholder="P90D", id="unused-input")
                yield Checkbox("Allow managing tokens", id="perm-tokens")
                yield Checkbox("Allow creating domains", id="perm-create")
                yield Checkbox("Allow deleting domains", id="perm-delete")
                yield Checkbox("Auto-create permissive policy on domain creation (auto_policy)", id="auto-policy")
            with Horizontal(id="modal-buttons"):
                yield Button("Create", id="create-btn", variant="success")
                yield Button("Cancel", id="cancel-btn")

    def on_mount(self) -> None:
        self.query_one("#name-input", Input).focus()

    @on(Button.Pressed, "#create-btn")
    def do_create(self) -> None:
        name = self.query_one("#name-input", Input).value.strip()
        if not name:
            self.app.push_screen(MessageModal("Error", "Token name is required.", is_error=True))
            return
        subnets_raw = self.query_one("#subnets-input", Input).value.strip()
        subnets = [s.strip() for s in subnets_raw.split(",") if s.strip()] if subnets_raw else []
        unused = self.query_one("#unused-input", Input).value.strip() or None
        self.dismiss({
            "name": name,
            "perm_manage_tokens": self.query_one("#perm-tokens", Checkbox).value,
            "perm_create_domain": self.query_one("#perm-create", Checkbox).value,
            "perm_delete_domain": self.query_one("#perm-delete", Checkbox).value,
            "auto_policy": self.query_one("#auto-policy", Checkbox).value,
            "allowed_subnets": subnets,
            "max_unused_period": unused,
        })

    @on(Button.Pressed, "#cancel-btn")
    def action_cancel(self) -> None:
        self.dismiss(None)


class AddPolicyModal(ModalScreen[dict | None]):
    """Form to add a policy to a token."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    RECORD_TYPES = ["(any)", "A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "SRV", "CAA"]

    def __init__(self, domains: list[str]):
        super().__init__()
        self._domains = domains

    def compose(self) -> ComposeResult:
        domain_opts = [("(any domain — default policy)", "")] + [(d, d) for d in self._domains]
        type_opts = [(t, "" if t == "(any)" else t) for t in self.RECORD_TYPES]

        with Container(id="modal-box", classes="wide"):
            yield Label("[bold cyan]Add Policy[/]", id="modal-title")
            with ScrollableContainer():
                yield Label("Domain  [dim](leave as 'any' for the required default policy)[/]")
                yield Select(options=domain_opts, id="domain-select", value="")
                yield Label("Subname  [dim](leave blank = all subnames)[/]")
                yield Input(placeholder="e.g. _acme-challenge", id="subname-input")
                yield Label("Record type")
                yield Select(options=type_opts, id="type-select", value="")
                yield Checkbox("Allow writes (unchecked = read-only / deny)", id="perm-write")
            with Horizontal(id="modal-buttons"):
                yield Button("Add Policy", id="add-btn", variant="success")
                yield Button("Cancel", id="cancel-btn")

    def on_mount(self) -> None:
        self.query_one("#subname-input", Input).focus()

    @on(Button.Pressed, "#add-btn")
    def do_add(self) -> None:
        domain = self.query_one("#domain-select", Select).value
        subname = self.query_one("#subname-input", Input).value.strip() or None
        rtype = self.query_one("#type-select", Select).value or None
        perm_write = self.query_one("#perm-write", Checkbox).value
        self.dismiss({
            "domain": domain or None,
            "subname": subname,
            "type": rtype,
            "perm_write": perm_write,
        })

    @on(Button.Pressed, "#cancel-btn")
    def action_cancel(self) -> None:
        self.dismiss(None)


class CreateDomainModal(ModalScreen[str | None]):
    """Form to register a new domain with deSEC."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Container(id="modal-box"):
            yield Label("[bold cyan]Register Domain[/]", id="modal-title")
            yield Label("Domain name  [dim](e.g. example.dedyn.io)[/]")
            yield Input(placeholder="example.dedyn.io", id="domain-input")
            with Horizontal(id="modal-buttons"):
                yield Button("Register", id="register-btn", variant="success")
                yield Button("Cancel", id="cancel-btn")

    def on_mount(self) -> None:
        self.query_one("#domain-input", Input).focus()

    @on(Button.Pressed, "#register-btn")
    @on(Input.Submitted, "#domain-input")
    def do_register(self) -> None:
        name = self.query_one("#domain-input", Input).value.strip()
        if not name:
            self.app.push_screen(MessageModal("Error", "Domain name is required.", is_error=True))
            return
        self.dismiss(name)

    @on(Button.Pressed, "#cancel-btn")
    def action_cancel(self) -> None:
        self.dismiss(None)


class AddEditRRSetModal(ModalScreen[dict | None]):
    """Form to add or edit a DNS RRset."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    RECORD_TYPES = [
        "A", "AAAA", "ALIAS", "CAA", "CNAME", "DS", "MX", "NS",
        "PTR", "SOA", "SRV", "SSHFP", "TLSA", "TXT",
    ]

    def __init__(self, subname: str = "", rtype: str = "A", ttl: int = 3600,
                 records: list[str] | None = None, editing: bool = False,
                 existing_names: list[str] | None = None):
        super().__init__()
        self._subname = subname
        self._rtype = rtype
        self._ttl = str(ttl)
        self._records_text = "\n".join(records or [])
        self._editing = editing
        self._existing_names = sorted(set(existing_names or []))

    def compose(self) -> ComposeResult:
        type_opts = [(t, t) for t in self.RECORD_TYPES]
        title = "[bold cyan]Edit RRset[/]" if self._editing else "[bold cyan]Add RRset[/]"
        cname_hidden = "" if self._rtype == "CNAME" else "hidden"
        pick_opts = [("— type destination manually —", "")] + [
            (n, n) for n in self._existing_names
        ]
        with Container(id="modal-box", classes="wide"):
            yield Label(title, id="modal-title")
            with ScrollableContainer():
                yield Label("Subname  [dim](blank or @ = apex)[/]")
                yield Input(
                    value="" if not self._subname else self._subname,
                    placeholder="e.g. www, mail, _acme-challenge  (blank = apex)",
                    id="subname-input",
                    disabled=self._editing,
                )
                yield Label("Record type")
                yield Select(options=type_opts, id="type-select",
                             value=self._rtype, disabled=self._editing)
                yield Label("TTL  [dim](seconds)[/]")
                yield Input(value=self._ttl, placeholder="3600", id="ttl-input")
                yield Label("Records  [dim](one per line, RDATA format)[/]")
                yield TextArea(self._records_text, id="records-area")
                yield Label(
                    "Quick-pick CNAME target  [dim](auto-fills above)[/]",
                    id="cname-pick-lbl", classes=cname_hidden,
                )
                yield Select(
                    options=pick_opts, id="cname-pick",
                    value="", classes=cname_hidden,
                )
            with Horizontal(id="modal-buttons"):
                yield Button("Save", id="save-btn", variant="success")
                yield Button("Cancel", id="cancel-btn")

    @on(Select.Changed, "#type-select")
    def on_type_changed(self, event: Select.Changed) -> None:
        is_cname = str(event.value) == "CNAME"
        for wid in ("#cname-pick-lbl", "#cname-pick"):
            self.query_one(wid).set_class(not is_cname, "hidden")

    @on(Select.Changed, "#cname-pick")
    def on_cname_pick(self, event: Select.Changed) -> None:
        val = str(event.value) if event.value else ""
        if val:
            self.query_one("#records-area", TextArea).load_text(val)

    @on(Button.Pressed, "#save-btn")
    def do_save(self) -> None:
        subname = self.query_one("#subname-input", Input).value.strip()
        if subname == "@":
            subname = ""
        try:
            ttl = int(self.query_one("#ttl-input", Input).value.strip())
        except ValueError:
            self.app.push_screen(MessageModal("Error", "TTL must be an integer.", is_error=True))
            return
        records_text = self.query_one("#records-area", TextArea).text.strip()
        records = [r.strip() for r in records_text.splitlines() if r.strip()]
        if not records:
            self.app.push_screen(MessageModal("Error", "At least one record value is required.", is_error=True))
            return
        rtype = self.query_one("#type-select", Select).value
        if not rtype:
            self.app.push_screen(MessageModal("Error", "Record type is required.", is_error=True))
            return
        self.dismiss({"subname": subname, "type": rtype, "ttl": ttl, "records": records})

    @on(Button.Pressed, "#cancel-btn")
    def action_cancel(self) -> None:
        self.dismiss(None)


# ──────────────────────────────────────────────────────────────────────────────
# Screens
# ──────────────────────────────────────────────────────────────────────────────

class LoginScreen(Screen):
    if TYPE_CHECKING:
        @property
        def app(self) -> DeSECApp: ...  # type: ignore[override]

    """Ask for the master API token."""

    def compose(self) -> ComposeResult:
        saved = load_env().get("DESEC_TOKEN", "")
        hint = "[dim]Token found in desec.env — connecting…[/]" if saved else "Enter your deSEC API token to continue:"
        yield Header()
        with Container(id="login-center"):
            with Container(id="login-container"):
                yield Label("[bold cyan]deSEC Token Manager[/]", id="login-title")
                yield Label(f"[dim]{ENV_PATH}[/]", id="login-env-path")
                yield Label(hint, id="login-hint")
                yield Input(password=True, placeholder="Paste token here…",
                            value=saved, id="token-input")
                yield Button("Connect", id="connect-btn", variant="primary")
                yield Label("", id="login-error")
        yield Footer()

    def on_mount(self) -> None:
        # Auto-connect if env token was loaded; otherwise focus the input immediately
        if load_env().get("DESEC_TOKEN"):
            self._try_connect(load_env()["DESEC_TOKEN"])
        else:
            self.query_one("#token-input", Input).focus()

    @on(Button.Pressed, "#connect-btn")
    @on(Input.Submitted, "#token-input")
    def do_login(self) -> None:
        token = self.query_one("#token-input", Input).value.strip()
        if not token:
            return
        self._try_connect(token)

    @work(exclusive=True)
    async def _try_connect(self, token: str) -> None:
        import asyncio
        err_label = self.query_one("#login-error", Label)
        try:
            await asyncio.get_event_loop().run_in_executor(None, list_tokens, token)
            self.app.master_token = token
            # Persist token to env file
            save_env({"DESEC_TOKEN": token})
            self.app.push_screen(TokenListScreen())
        except httpx.HTTPStatusError as e:
            err_label.update(f"[red]Auth failed: {e.response.status_code}[/]")
        except Exception as e:
            err_label.update(f"[red]Error: {e}[/]")


class PolicyScreen(Screen):
    if TYPE_CHECKING:
        @property
        def app(self) -> DeSECApp: ...  # type: ignore[override]

    """View and manage policies for a single token."""

    BINDINGS = [
        Binding("escape,b", "go_back", "Back"),
        Binding("a", "add_policy", "Add Policy"),
        Binding("d", "delete_policy", "Delete Selected"),
        Binding("r", "refresh", "Refresh"),
    ]

    def __init__(self, token_id: str, token_name: str):
        super().__init__()
        self._token_id = token_id
        self._token_name = token_name
        self._policies: list[dict] = []
        self._domains: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="policy-screen"):
            yield Label(f"[bold cyan]Policies — {self._token_name}[/]", id="policy-title")
            yield Static(
                "[dim]A deny-all default policy (domain=any, subname=any, type=any, write=No) "
                "must exist before specific policies can be added.[/]",
                id="policy-hint"
            )
            yield DataTable(id="policy-table", cursor_type="row")
            with Horizontal(id="policy-actions"):
                yield Button("Add Policy (a)", id="add-btn", variant="success")
                yield Button("Delete Selected (d)", id="del-btn", variant="error")
                yield Button("Back (Esc)", id="back-btn")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#policy-table", DataTable)
        table.add_columns("ID", "Domain", "Subname", "Type", "Write?")
        self.load_data()

    @work(exclusive=True)
    async def load_data(self) -> None:
        import asyncio
        token = self.app.master_token
        try:
            self._policies = await asyncio.get_event_loop().run_in_executor(
                None, list_policies, token, self._token_id)
            self._domains = [d["name"] for d in await asyncio.get_event_loop().run_in_executor(
                None, list_domains, token)]
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))
            return
        table = self.query_one("#policy-table", DataTable)
        table.clear()
        for p in self._policies:
            table.add_row(
                p.get("id", ""),
                p.get("domain") or "[dim](any)[/]",
                p.get("subname") or "[dim](any)[/]",
                p.get("type") or "[dim](any)[/]",
                "[green]Yes[/]" if p.get("perm_write") else "[red]No[/]",
                key=p.get("id"),
            )

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self.load_data()

    def action_add_policy(self) -> None:
        self.app.push_screen(AddPolicyModal(self._domains), self._handle_add_policy)

    def _handle_add_policy(self, result: dict | None) -> None:
        if result is None:
            return
        self._do_add_policy(result)

    @work(exclusive=True)
    async def _do_add_policy(self, data: dict) -> None:
        import asyncio
        token = self.app.master_token
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: create_policy(
                    token, self._token_id,
                    data["domain"], data["subname"], data["type"], data["perm_write"]
                )
            )
            self.load_data()
        except httpx.HTTPStatusError as e:
            body = e.response.text
            # Auto-fix: deSEC requires a default policy before any scoped policy.
            if e.response.status_code == 400 and "Policy precedence" in body:
                def _cb_fix(ok: bool | None) -> None:
                    if ok:
                        self._auto_create_default_then_retry(data)
                self.app.push_screen(
                    ConfirmModal(
                        "deSEC requires a [bold]default policy[/] (all fields = any) "
                        "before scoped policies can be added.\n\n"
                        "Auto-create a read-only default policy first, then add yours?"
                    ),
                    _cb_fix,
                )
            else:
                self.app.push_screen(MessageModal("API Error", f"{e.response.status_code}: {body}", is_error=True))
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))

    @work(exclusive=True)
    async def _auto_create_default_then_retry(self, data: dict) -> None:
        """Create the required default (catch-all read-only) policy, then add the intended policy."""
        import asyncio
        token = self.app.master_token
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: create_policy(token, self._token_id, None, None, None, False)
            )
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: create_policy(
                    token, self._token_id,
                    data["domain"], data["subname"], data["type"], data["perm_write"]
                )
            )
            self.load_data()
        except httpx.HTTPStatusError as e:
            body = e.response.text
            self.app.push_screen(MessageModal("API Error", f"{e.response.status_code}: {body}", is_error=True))
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))

    def action_delete_policy(self) -> None:
        table = self.query_one("#policy-table", DataTable)
        if table.cursor_row < 0 or not self._policies:
            return
        if table.cursor_row >= len(self._policies):
            return
        policy = self._policies[table.cursor_row]
        _pid = policy["id"]
        def _cb_del_pol(ok: bool | None) -> None:
            if ok:
                self._do_delete_policy(_pid)
        self.app.push_screen(
            ConfirmModal(f"Delete policy [bold]{_pid}[/]?"), _cb_del_pol
        )

    @work(exclusive=True)
    async def _do_delete_policy(self, policy_id: str) -> None:
        import asyncio
        token = self.app.master_token
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: delete_policy(token, self._token_id, policy_id))
            self.load_data()
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))

    @on(Button.Pressed, "#add-btn")
    def on_add(self) -> None:
        self.action_add_policy()

    @on(Button.Pressed, "#del-btn")
    def on_del(self) -> None:
        self.action_delete_policy()

    @on(Button.Pressed, "#back-btn")
    def on_back(self) -> None:
        self.action_go_back()


class TokenListScreen(Screen):
    """Main screen — list all tokens."""
    if TYPE_CHECKING:
        @property
        def app(self) -> DeSECApp: ...  # type: ignore[override]


    BINDINGS = [
        Binding("n", "new_token",      "New Token"),
        Binding("p", "view_policies",  "Policies"),
        Binding("m", "manage_domains", "Domains"),
        Binding("k", "ddns_key",       "DDNS Key"),
        Binding("c", "cert_key",       "Cert Key"),
        Binding("u", "cert_multi",     "Multi-Cert"),
        Binding("d", "delete_token",   "Delete"),
        Binding("r", "refresh",        "Refresh"),
        Binding("q", "quit_app",       "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="token-screen"):
            yield Label("[bold cyan]deSEC API Tokens[/]", id="token-title")
            yield DataTable(id="token-table", cursor_type="row")
            with Horizontal(id="token-actions"):
                yield Button("New Token (n)",  id="new-btn",  variant="success")
                yield Button("Policies (p)",   id="pol-btn",  variant="primary")
                yield Button("Domains (m)",    id="dom-btn")
                yield Button("DDNS Key (k)",   id="ddns-btn", variant="warning")
                yield Button("Cert Key (c)",   id="cert-btn", variant="warning")
                yield Button("Multi-Cert (u)", id="mcrt-btn", variant="warning")
                yield Button("Delete (d)",     id="del-btn",  variant="error")
                yield Button("Refresh (r)",    id="ref-btn")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#token-table", DataTable)
        table.add_columns("Name", "ID", "Manage Tokens?", "Create Domain?", "Delete Domain?", "Subnets", "Policies?")
        self.load_tokens()

    @work(exclusive=True)
    async def load_tokens(self) -> None:
        import asyncio
        try:
            tokens = await asyncio.get_event_loop().run_in_executor(
                None, list_tokens, self.app.master_token)
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))
            return
        self.app._tokens = tokens
        table = self.query_one("#token-table", DataTable)
        table.clear()
        for t in tokens:
            subnets = ", ".join(t.get("allowed_subnets") or []) or "[dim]any[/]"
            has_policies = "[green]Yes[/]" if t.get("policies") else "[dim]–[/]"
            table.add_row(
                t.get("name") or "[dim]unnamed[/]",
                t.get("id", ""),
                "[green]Yes[/]" if t.get("perm_manage_tokens") else "[dim]No[/]",
                "[green]Yes[/]" if t.get("perm_create_domain") else "[dim]No[/]",
                "[green]Yes[/]" if t.get("perm_delete_domain") else "[dim]No[/]",
                subnets,
                has_policies,
                key=t.get("id"),
            )

    def _selected_token(self) -> dict | None:
        table = self.query_one("#token-table", DataTable)
        tokens = getattr(self.app, "_tokens", [])
        if not tokens or table.cursor_row < 0 or table.cursor_row >= len(tokens):
            return None
        return tokens[table.cursor_row]

    def action_new_token(self) -> None:
        self.app.push_screen(CreateTokenModal(), self._handle_new_token)

    def _handle_new_token(self, result: dict | None) -> None:
        if result is None:
            return
        self._do_create_token(result)

    @work(exclusive=True)
    async def _do_create_token(self, data: dict) -> None:
        import asyncio
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: create_token(
                    self.app.master_token, data["name"],
                    data["perm_manage_tokens"], data["perm_create_domain"],
                    data["perm_delete_domain"], data["allowed_subnets"],
                    data["max_unused_period"], data["auto_policy"],
                )
            )
            secret = result.get("token", "[not returned]")
            self.app.push_screen(NewSecretModal(data["name"], secret))
            self.load_tokens()
        except httpx.HTTPStatusError as e:
            self.app.push_screen(MessageModal("API Error", f"{e.response.status_code}: {e.response.text}", is_error=True))
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))

    def action_view_policies(self) -> None:
        t = self._selected_token()
        if t:
            self.app.push_screen(PolicyScreen(t["id"], t.get("name", t["id"])))

    def action_manage_domains(self) -> None:
        self.app.push_screen(DomainListScreen())

    # ── Scoped-key provisioning ───────────────────────────────────────────────

    def action_ddns_key(self) -> None:
        self._load_domains_then_open("ddns")

    def action_cert_key(self) -> None:
        self._load_domains_then_open("cert")

    def action_cert_multi(self) -> None:
        self._load_domains_then_open("multi")

    @work(exclusive=True)
    async def _load_domains_then_open(self, target: str) -> None:
        import asyncio
        try:
            domains = await asyncio.get_event_loop().run_in_executor(
                None, lambda: [d["name"] for d in list_domains(self.app.master_token)])
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))
            return
        if not domains:
            self.app.push_screen(MessageModal(
                "No Domains", "Register at least one domain before creating scoped keys."))
            return
        if target == "ddns":
            self.app.push_screen(DdnsAddModal(domains), self._handle_ddns)
        elif target == "cert":
            self.app.push_screen(CertAddModal(domains), self._handle_cert)
        else:
            self.app.push_screen(CertMultiScreen(domains))

    def _handle_ddns(self, result: dict | None) -> None:
        if result:
            self._do_provision_ddns(result)

    def _handle_cert(self, result: dict | None) -> None:
        if result:
            self._do_provision_cert(result)

    @work(exclusive=True)
    async def _do_provision_ddns(self, data: dict) -> None:
        import asyncio
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: provision_ddns_token(
                    self.app.master_token, data["name"],
                    data["domain"], data["subname"],
                    data["ipv4"], data["ipv6"],
                ))
            secret = result.get("token", "[not returned]")
            self.app.push_screen(NewSecretModal(data["name"], secret))
            self.load_tokens()
        except httpx.HTTPStatusError as e:
            self.app.push_screen(MessageModal("API Error",
                f"{e.response.status_code}: {e.response.text}", is_error=True))
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))

    @work(exclusive=True)
    async def _do_provision_cert(self, data: dict) -> None:
        import asyncio
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: provision_cert_token(
                    self.app.master_token, data["name"],
                    data["domain"], data["subname"],
                    data["ipv4"], data["ipv6"], data["cname"],
                ))
            secret = result.get("token", "[not returned]")
            self.app.push_screen(NewSecretModal(data["name"], secret))
            self.load_tokens()
        except httpx.HTTPStatusError as e:
            self.app.push_screen(MessageModal("API Error",
                f"{e.response.status_code}: {e.response.text}", is_error=True))
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))

    # ─────────────────────────────────────────────────────────────────────────

    def action_delete_token(self) -> None:
        t = self._selected_token()
        if not t:
            return
        _tid = t["id"]
        def _cb_del_tok(ok: bool | None) -> None:
            if ok:
                self._do_delete(_tid)
        self.app.push_screen(
            ConfirmModal(f"Delete token [bold]{t.get('name', _tid)}[/]?"), _cb_del_tok
        )

    @work(exclusive=True)
    async def _do_delete(self, token_id: str) -> None:
        import asyncio
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: delete_token(self.app.master_token, token_id))
            self.load_tokens()
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))

    def action_refresh(self) -> None:
        self.load_tokens()

    def action_quit_app(self) -> None:
        self.app.exit()

    @on(Button.Pressed, "#new-btn")
    def on_new(self)  -> None: self.action_new_token()
    @on(Button.Pressed, "#pol-btn")
    def on_pol(self)  -> None: self.action_view_policies()
    @on(Button.Pressed, "#dom-btn")
    def on_dom(self)  -> None: self.action_manage_domains()
    @on(Button.Pressed, "#ddns-btn")
    def on_ddns(self) -> None: self.action_ddns_key()
    @on(Button.Pressed, "#cert-btn")
    def on_cert(self) -> None: self.action_cert_key()
    @on(Button.Pressed, "#mcrt-btn")
    def on_mcrt(self) -> None: self.action_cert_multi()
    @on(Button.Pressed, "#del-btn")
    def on_del(self)  -> None: self.action_delete_token()
    @on(Button.Pressed, "#ref-btn")
    def on_ref(self)  -> None: self.action_refresh()


class DomainListScreen(Screen):
    """List all domains; create, delete, or manage their DNS records."""
    if TYPE_CHECKING:
        @property
        def app(self) -> DeSECApp: ...  # type: ignore[override]


    BINDINGS = [
        Binding("escape,b", "go_back", "Back"),
        Binding("c", "create_domain", "Create"),
        Binding("d", "delete_domain", "Delete"),
        Binding("m", "manage_records", "Manage Records"),
        Binding("r", "refresh", "Refresh"),
    ]

    def __init__(self):
        super().__init__()
        self._domains: list[dict] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="domain-screen"):
            yield Label("[bold cyan]deSEC Domains[/]", id="domain-title")
            yield DataTable(id="domain-table", cursor_type="row")
            with Horizontal(id="domain-actions"):
                yield Button("Create (c)", id="create-btn", variant="success")
                yield Button("Records (m)", id="records-btn", variant="primary")
                yield Button("Delete (d)", id="del-btn", variant="error")
                yield Button("Refresh (r)", id="ref-btn")
                yield Button("Back (Esc)", id="back-btn")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#domain-table", DataTable)
        table.add_columns("Name", "Created", "Min TTL", "Published")
        self.load_data()

    @work(exclusive=True)
    async def load_data(self) -> None:
        import asyncio
        try:
            self._domains = await asyncio.get_event_loop().run_in_executor(
                None, list_domains, self.app.master_token)
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))
            return
        table = self.query_one("#domain-table", DataTable)
        table.clear()
        for d in self._domains:
            created = (d.get("created") or "")[:10]
            table.add_row(
                d.get("name", ""),
                created,
                str(d.get("minimum_ttl", "")),
                "[green]Yes[/]" if d.get("published") else "[dim]–[/]",
                key=d.get("name"),
            )

    def _selected_domain(self) -> dict | None:
        table = self.query_one("#domain-table", DataTable)
        if not self._domains or table.cursor_row < 0 or table.cursor_row >= len(self._domains):
            return None
        return self._domains[table.cursor_row]

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self.load_data()

    def action_create_domain(self) -> None:
        self.app.push_screen(CreateDomainModal(), self._handle_create)

    def _handle_create(self, name: str | None) -> None:
        if name is None:
            return
        self._do_create_domain(name)

    @work(exclusive=True)
    async def _do_create_domain(self, name: str) -> None:
        import asyncio
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: create_domain(self.app.master_token, name))
            self.load_data()
        except httpx.HTTPStatusError as e:
            self.app.push_screen(MessageModal("API Error", f"{e.response.status_code}: {e.response.text}", is_error=True))
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))

    def action_delete_domain(self) -> None:
        d = self._selected_domain()
        if not d:
            return
        name = d.get("name", "")
        def _cb_del_dom(ok: bool | None) -> None:
            if ok:
                self._do_delete_domain(name)
        self.app.push_screen(
            ConfirmModal(f"Delete domain [bold]{name}[/]?\n[red]All DNS records will be removed![/]"),
            _cb_del_dom,
        )

    @work(exclusive=True)
    async def _do_delete_domain(self, name: str) -> None:
        import asyncio
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: delete_domain(self.app.master_token, name))
            self.load_data()
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))

    def action_manage_records(self) -> None:
        d = self._selected_domain()
        if d:
            self.app.push_screen(RRSetScreen(d["name"]))

    @on(Button.Pressed, "#create-btn")
    def on_create(self) -> None: self.action_create_domain()
    @on(Button.Pressed, "#records-btn")
    def on_records(self) -> None: self.action_manage_records()
    @on(Button.Pressed, "#del-btn")
    def on_del(self) -> None: self.action_delete_domain()
    @on(Button.Pressed, "#ref-btn")
    def on_ref(self) -> None: self.action_refresh()
    @on(Button.Pressed, "#back-btn")
    def on_back(self) -> None: self.action_go_back()


class RRSetScreen(Screen):
    if TYPE_CHECKING:
        @property
        def app(self) -> DeSECApp: ...  # type: ignore[override]

    """View and manage DNS records (RRsets) for a single domain."""

    BINDINGS = [
        Binding("escape,b", "go_back", "Back"),
        Binding("a", "add_rrset", "Add"),
        Binding("e", "edit_rrset", "Edit"),
        Binding("d", "delete_rrset", "Delete"),
        Binding("r", "refresh", "Refresh"),
    ]

    def __init__(self, domain: str):
        super().__init__()
        self._domain = domain
        self._rrsets: list[dict] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="rrset-screen"):
            yield Label(f"[bold cyan]DNS Records — {self._domain}[/]", id="rrset-title")
            yield DataTable(id="rrset-table", cursor_type="row")
            with Horizontal(id="rrset-actions"):
                yield Button("Add (a)", id="add-btn", variant="success")
                yield Button("Edit (e)", id="edit-btn", variant="primary")
                yield Button("Delete (d)", id="del-btn", variant="error")
                yield Button("Refresh (r)", id="ref-btn")
                yield Button("Back (Esc)", id="back-btn")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#rrset-table", DataTable)
        table.add_columns("Subname", "Type", "TTL", "Records")
        self.load_data()

    @work(exclusive=True)
    async def load_data(self) -> None:
        import asyncio
        try:
            self._rrsets = await asyncio.get_event_loop().run_in_executor(
                None, list_rrsets, self.app.master_token, self._domain)
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))
            return
        table = self.query_one("#rrset-table", DataTable)
        table.clear()
        for rr in self._rrsets:
            subname = rr.get("subname") or "[dim]@[/]"
            records = rr.get("records", [])
            rec_display = records[0] if records else ""
            if len(records) > 1:
                rec_display += f" [dim](+{len(records) - 1} more)[/]"
            table.add_row(
                subname,
                rr.get("type", ""),
                str(rr.get("ttl", "")),
                rec_display,
                key=f"{rr.get('subname', '')}|{rr.get('type', '')}",
            )

    def _selected_rrset(self) -> dict | None:
        table = self.query_one("#rrset-table", DataTable)
        if not self._rrsets or table.cursor_row < 0 or table.cursor_row >= len(self._rrsets):
            return None
        return self._rrsets[table.cursor_row]

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self.load_data()

    def _existing_fqdns(self, exclude_rr: dict | None = None) -> list[str]:
        out = []
        for rr in self._rrsets:
            if rr is exclude_rr:
                continue
            sub = rr.get("subname", "")
            out.append(f"{sub}.{self._domain}." if sub else f"{self._domain}.")
        return sorted(set(out))

    def action_add_rrset(self) -> None:
        self.app.push_screen(
            AddEditRRSetModal(existing_names=self._existing_fqdns()),
            self._handle_add,
        )

    def _handle_add(self, result: dict | None) -> None:
        if result is None:
            return
        self._do_save_rrset(result, editing=False)

    def action_edit_rrset(self) -> None:
        rr = self._selected_rrset()
        if not rr:
            return
        self.app.push_screen(
            AddEditRRSetModal(
                subname=rr.get("subname", ""),
                rtype=rr.get("type", "A"),
                ttl=rr.get("ttl", 3600),
                records=rr.get("records", []),
                editing=True,
                existing_names=self._existing_fqdns(exclude_rr=rr),
            ),
            self._handle_edit,
        )

    def _handle_edit(self, result: dict | None) -> None:
        if result is None:
            return
        self._do_save_rrset(result, editing=True)

    @work(exclusive=True)
    async def _do_save_rrset(self, data: dict, editing: bool) -> None:
        import asyncio
        token = self.app.master_token
        try:
            if editing:
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: update_rrset(
                        token, self._domain,
                        data["subname"], data["type"], data["ttl"], data["records"],
                    )
                )
            else:
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: create_rrset(
                        token, self._domain,
                        data["subname"], data["type"], data["ttl"], data["records"],
                    )
                )
            self.load_data()
        except httpx.HTTPStatusError as e:
            self.app.push_screen(MessageModal("API Error", f"{e.response.status_code}: {e.response.text}", is_error=True))
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))

    def action_delete_rrset(self) -> None:
        rr = self._selected_rrset()
        if not rr:
            return
        display_subname = rr.get("subname") or "@"
        rtype = rr.get("type", "")
        _sub = rr.get("subname", "")
        def _cb_del_rr(ok: bool | None) -> None:
            if ok:
                self._do_delete_rrset(_sub, rtype)
        self.app.push_screen(
            ConfirmModal(f"Delete [bold]{display_subname} {rtype}[/] from [bold]{self._domain}[/]?"),
            _cb_del_rr,
        )

    @work(exclusive=True)
    async def _do_delete_rrset(self, subname: str, rtype: str) -> None:
        import asyncio
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: delete_rrset(self.app.master_token, self._domain, subname, rtype))
            self.load_data()
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))

    @on(Button.Pressed, "#add-btn")
    def on_add(self) -> None: self.action_add_rrset()
    @on(Button.Pressed, "#edit-btn")
    def on_edit(self) -> None: self.action_edit_rrset()
    @on(Button.Pressed, "#del-btn")
    def on_del(self) -> None: self.action_delete_rrset()
    @on(Button.Pressed, "#ref-btn")
    def on_ref(self) -> None: self.action_refresh()
    @on(Button.Pressed, "#back-btn")
    def on_back(self) -> None: self.action_go_back()


# ──────────────────────────────────────────────────────────────────────────────
# Scoped-key provisioning modals / screens
# ──────────────────────────────────────────────────────────────────────────────

class DdnsAddModal(ModalScreen):
    """Wizard: provision a DDNS-scoped API token for a specific hostname."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, domains: list[str]):
        super().__init__()
        self._domains = sorted(domains)

    def compose(self) -> ComposeResult:
        domain_opts = [(d, d) for d in self._domains]
        default_domain = self._domains[0] if self._domains else ""
        with Container(id="modal-box", classes="wide"):
            yield Label("[bold cyan]Provision DDNS Token[/]", id="modal-title")
            with ScrollableContainer():
                yield Static(
                    "[dim]Creates A + AAAA write access for one hostname. "
                    "The generated token cannot touch any other record, type, or domain.[/]",
                    id="modal-body",
                )
                yield Label("Domain")
                yield Select(options=domain_opts, id="ddns-domain", value=default_domain)
                yield Label("Subdomain label  [dim](blank = apex @)[/]")
                yield Input(placeholder="home  or  server  or  <blank>", id="ddns-subname")
                yield Label("Initial IPv4  [dim](optional — sets A record now)[/]")
                yield Input(placeholder="1.2.3.4", id="ddns-ipv4")
                yield Label("Initial IPv6  [dim](optional — sets AAAA record now)[/]")
                yield Input(placeholder="2001:db8::1", id="ddns-ipv6")
                yield Label("Token name")
                yield Input(placeholder="my-server-ddns", id="ddns-tokname")
            with Horizontal(id="modal-buttons"):
                yield Button("Create", id="create-btn", variant="success")
                yield Button("Cancel", id="cancel-btn")

    def on_mount(self) -> None:
        self.query_one("#ddns-subname", Input).focus()

    @on(Button.Pressed, "#create-btn")
    def do_create(self) -> None:
        domain  = str(self.query_one("#ddns-domain",  Select).value)
        subname = self.query_one("#ddns-subname",  Input).value.strip()
        ipv4    = self.query_one("#ddns-ipv4",     Input).value.strip() or None
        ipv6    = self.query_one("#ddns-ipv6",     Input).value.strip() or None
        name    = self.query_one("#ddns-tokname",  Input).value.strip()
        if not domain:
            self.app.push_screen(MessageModal("Error", "Domain is required.", is_error=True))
            return
        if not name:
            host = f"{subname}.{domain}" if subname else domain
            name = f"{host}-ddns"
        self.dismiss({"domain": domain, "subname": subname,
                      "ipv4": ipv4, "ipv6": ipv6, "name": name})

    @on(Button.Pressed, "#cancel-btn")
    def action_cancel(self) -> None:
        self.dismiss(None)


class CertAddModal(ModalScreen):
    """Wizard: provision a single-domain cert-scoped API token."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, domains: list[str]):
        super().__init__()
        self._domains = sorted(domains)

    def compose(self) -> ComposeResult:
        domain_opts = [(d, d) for d in self._domains]
        default_domain = self._domains[0] if self._domains else ""
        with Container(id="modal-box", classes="wide"):
            yield Label("[bold cyan]Provision Single-Domain Cert Token[/]", id="modal-title")
            with ScrollableContainer():
                yield Static(
                    "[dim]Optionally sets initial address/CNAME records (using your master token), "
                    "then creates a token scoped only to TXT writes at "
                    "[bold]_acme-challenge.<hostname>[/] — DNS-01 ACME challenges only.[/]",
                    id="modal-body",
                )
                yield Label("Domain")
                yield Select(options=domain_opts, id="cert-domain", value=default_domain)
                yield Label("Subdomain label  [dim](blank = apex @)[/]")
                yield Input(placeholder="www  or  api  or  <blank>", id="cert-subname")
                yield Label("Initial IPv4  [dim](sets A record now — not granted to token)[/]")
                yield Input(placeholder="1.2.3.4", id="cert-ipv4")
                yield Label("Initial IPv6  [dim](sets AAAA record now — not granted to token)[/]")
                yield Input(placeholder="2001:db8::1", id="cert-ipv6")
                yield Label("Initial CNAME  [dim](alternative to A/AAAA — not granted to token)[/]")
                yield Input(placeholder="target.example.com.", id="cert-cname")
                yield Label("Token name")
                yield Input(placeholder="my-server-cert", id="cert-tokname")
            with Horizontal(id="modal-buttons"):
                yield Button("Create", id="create-btn", variant="success")
                yield Button("Cancel", id="cancel-btn")

    def on_mount(self) -> None:
        self.query_one("#cert-subname", Input).focus()

    @on(Button.Pressed, "#create-btn")
    def do_create(self) -> None:
        domain  = str(self.query_one("#cert-domain",  Select).value)
        subname = self.query_one("#cert-subname",  Input).value.strip()
        ipv4    = self.query_one("#cert-ipv4",     Input).value.strip() or None
        ipv6    = self.query_one("#cert-ipv6",     Input).value.strip() or None
        cname   = self.query_one("#cert-cname",    Input).value.strip() or None
        name    = self.query_one("#cert-tokname",  Input).value.strip()
        if not domain:
            self.app.push_screen(MessageModal("Error", "Domain is required.", is_error=True))
            return
        if cname and (ipv4 or ipv6):
            self.app.push_screen(MessageModal(
                "Error", "Specify either CNAME or address records — not both.", is_error=True))
            return
        if not name:
            host = f"{subname}.{domain}" if subname else domain
            name = f"{host}-cert"
        self.dismiss({"domain": domain, "subname": subname,
                      "ipv4": ipv4, "ipv6": ipv6, "cname": cname, "name": name})

    @on(Button.Pressed, "#cancel-btn")
    def action_cancel(self) -> None:
        self.dismiss(None)


class CertMultiScreen(Screen):
    """Full-screen wizard: provision a multi-domain cert-scoped token (TXT-only, no address writes)."""
    if TYPE_CHECKING:
        @property
        def app(self) -> DeSECApp: ...  # type: ignore[override]


    BINDINGS = [
        Binding("escape,b", "go_back",    "Cancel"),
        Binding("a",        "add_entry",  "Add"),
        Binding("d",        "del_entry",  "Remove"),
    ]

    def __init__(self, domains: list[str]):
        super().__init__()
        self._domains = sorted(domains)
        self._entries: list[tuple[str, str]] = []  # [(domain, subname), ...]

    def compose(self) -> ComposeResult:
        domain_opts = [(d, d) for d in self._domains]
        default_domain = self._domains[0] if self._domains else ""
        yield Header()
        with Vertical(id="certmulti-screen"):
            yield Label("[bold cyan]Provision Multi-Domain Cert Token[/]", id="certmulti-title")
            yield Static(
                "[dim]Grants TXT write access at [bold]_acme-challenge.<hostname>[/] for each entry. "
                "No address records are touched or granted — strict least-privilege.[/]"
            )
            yield DataTable(id="certmulti-table", cursor_type="row")
            with Horizontal(id="certmulti-add-row"):
                yield Select(options=domain_opts, id="cm-domain", value=default_domain)
                yield Input(placeholder="subname (blank = apex)", id="cm-subname")
                yield Button("Add (a)", id="add-btn", variant="success")
            yield Label("Token name")
            yield Input(placeholder="multi-cert", id="certmulti-name")
            with Horizontal(id="certmulti-actions"):
                yield Button("Remove Selected (d)", id="del-btn", variant="error")
                yield Button("Create Token",         id="create-btn", variant="primary")
                yield Button("Cancel (Esc)",         id="cancel-btn")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#certmulti-table", DataTable).add_columns(
            "Domain", "Subname", "ACME Challenge Subname")

    def action_go_back(self) -> None: self.app.pop_screen()

    def action_add_entry(self) -> None:
        domain  = str(self.query_one("#cm-domain",  Select).value)
        subname = self.query_one("#cm-subname", Input).value.strip()
        if not domain:
            self.app.push_screen(MessageModal("Error", "Domain is required.", is_error=True))
            return
        entry = (domain, subname)
        if entry in self._entries:
            self.app.push_screen(MessageModal(
                "Duplicate", f"{domain} ({subname or '@'}) is already in the list."))
            return
        self._entries.append(entry)
        acme = _acme_subname(subname)
        self.query_one("#certmulti-table", DataTable).add_row(domain, subname or "@", acme)

    def action_del_entry(self) -> None:
        t = self.query_one("#certmulti-table", DataTable)
        if not self._entries or t.cursor_row < 0 or t.cursor_row >= len(self._entries):
            return
        self._entries.pop(t.cursor_row)
        t.clear()
        for domain, subname in self._entries:
            t.add_row(domain, subname or "@", _acme_subname(subname))

    @on(Button.Pressed, "#add-btn")
    def on_add(self) -> None: self.action_add_entry()

    @on(Button.Pressed, "#del-btn")
    def on_del(self) -> None: self.action_del_entry()

    @on(Button.Pressed, "#cancel-btn")
    def on_cancel(self) -> None: self.action_go_back()

    @on(Button.Pressed, "#create-btn")
    def on_create(self) -> None:
        if not self._entries:
            self.app.push_screen(MessageModal("Error", "Add at least one domain entry.", is_error=True))
            return
        name = self.query_one("#certmulti-name", Input).value.strip() or "multi-cert"
        self._do_provision(name, list(self._entries))

    @work(exclusive=True)
    async def _do_provision(self, name: str, entries: list[tuple[str, str]]) -> None:
        import asyncio
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: provision_cert_multi_token(self.app.master_token, name, entries))
            secret = result.get("token", "[not returned]")
            self.app.push_screen(NewSecretModal(name, secret))
            self.app.pop_screen()
        except httpx.HTTPStatusError as e:
            self.app.push_screen(MessageModal("API Error",
                f"{e.response.status_code}: {e.response.text}", is_error=True))
        except Exception as e:
            self.app.push_screen(MessageModal("Error", str(e), is_error=True))


# ──────────────────────────────────────────────────────────────────────────────
# App
# ──────────────────────────────────────────────────────────────────────────────

CSS = """
/* Global */
Screen { background: $surface; }
.hidden { display: none; }

/* Login */
#login-center {
    width: 100%;
    height: 1fr;
    align: center middle;
}
#login-container {
    width: 60;
    max-width: 95%;
    height: auto;
    padding: 2 3;
    border: round $primary;
    background: $panel;
}
#login-title { text-align: center; margin-bottom: 1; }
#login-env-path { text-align: center; color: $text-muted; margin-bottom: 1; }
#login-error { color: $error; margin-top: 1; }
#login-container Input { margin-bottom: 1; }
/* Ensure Input text and border are visible in Textual 8 dark theme.
   $border-blurred (#191919) is nearly invisible on $surface (#1e1e1e),
   so override to a medium-gray border that's always distinguishable.
   App CSS overrides DEFAULT_CSS regardless of :focus specificity, so we
   must also re-declare the focused border here to restore the blue ring. */
Input {
    color: $foreground;
    border: tall $foreground-darken-3;
}
Input:focus {
    border: tall $border;
}

/* Token list */
#token-screen { padding: 1 2; }
#token-title  { margin-bottom: 1; }
#token-actions { height: auto; margin-top: 1; }
#token-actions Button { margin-right: 1; }

/* Policy screen */
#policy-screen { padding: 1 2; }
#policy-title  { margin-bottom: 1; }
#policy-hint   { color: $text-muted; margin-bottom: 1; }
#policy-actions { height: auto; margin-top: 1; }
#policy-actions Button { margin-right: 1; }

/* Domain list screen */
#domain-screen { padding: 1 2; }
#domain-title  { margin-bottom: 1; }
#domain-actions { height: auto; margin-top: 1; }
#domain-actions Button { margin-right: 1; }

/* RRset screen */
#rrset-screen  { padding: 1 2; }
#rrset-title   { margin-bottom: 1; }
#rrset-actions { height: auto; margin-top: 1; }
#rrset-actions Button { margin-right: 1; }

/* Modals */
ModalScreen {
    align: center middle;
    background: $background 60%;
}
#modal-box {
    width: 60;
    max-width: 95%;
    height: auto;
    max-height: 80vh;
    padding: 2 3;
    border: round $accent;
    background: $panel;
}
#modal-box.wide { width: 80; max-width: 95%; }
#modal-title { margin-bottom: 1; }
#modal-body  { margin-bottom: 1; }
#modal-buttons { height: auto; margin-top: 1; }
#modal-buttons Button { margin-right: 1; }
ModalScreen Input, ModalScreen Select { margin-bottom: 1; color: $foreground; }
ModalScreen Label { margin-top: 1; }
ModalScreen Checkbox { margin-bottom: 1; }
ModalScreen TextArea { height: 8; margin-bottom: 1; }
/* height: auto (not 1fr) because 1fr in an auto-height parent collapses to
   zero content rows for children, making Input text invisible in Textual 8. */
ScrollableContainer { height: auto; max-height: 40; }

/* CertMultiScreen */
#certmulti-screen  { padding: 1 2; }
#certmulti-title   { margin-bottom: 1; }
#certmulti-table   { height: 1fr; max-height: 16; margin-bottom: 1; }
#certmulti-add-row { height: auto; margin-bottom: 1; }
#certmulti-add-row Select { width: 1fr; margin-right: 1; }
#certmulti-add-row Input  { width: 1fr; margin-right: 1; }
#certmulti-add-row Button { width: auto; }
#certmulti-screen Label   { margin-top: 1; margin-bottom: 0; }
#certmulti-screen Input   { margin-bottom: 1; }
#certmulti-actions { height: auto; margin-top: 1; }
#certmulti-actions Button { margin-right: 1; }
"""


class DeSECApp(App):
    TITLE = "deSEC Token Manager"
    CSS = CSS
    BINDINGS = [Binding("ctrl+c", "quit", "Quit", show=False)]

    master_token: str = ""
    _tokens: list = []

    def on_mount(self) -> None:
        ensure_env_complete()
        self.push_screen(LoginScreen())


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _build_cli_parser() -> argparse.ArgumentParser:
    env = load_env()
    p = argparse.ArgumentParser(
        prog="desec-api",
        description="deSEC Token & DNS Manager — TUI and CLI",
        epilog=(
            "Config: ~/.config/mech-goodies/desec.env  |  "
            "Deps: pip install textual httpx  |  "
            "DESEC_TOKEN env var is also accepted."
        ),
    )
    p.add_argument("--token",  default=os.environ.get("DESEC_TOKEN") or env.get("DESEC_TOKEN", ""),
                   help="deSEC API token (env: DESEC_TOKEN, or desec.env)")
    p.add_argument("--output", "-o", choices=["table", "json", "yaml"], default="table",
                   help="Output format — table (default), json, or yaml")
    p.add_argument("--ui", action="store_true",
                   help="Launch the interactive TUI (default when no subcommand given)")

    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    # ── token ────────────────────────────────────────────────────────────────
    tp = sub.add_parser("token", help="Manage API tokens")
    tsub = tp.add_subparsers(dest="token_cmd", metavar="ACTION")

    tsub.add_parser("list", help="List all tokens")

    tc = tsub.add_parser("create", help="Create a new token")
    tc.add_argument("name", help="Token name")
    tc.add_argument("--perm-manage-tokens", action="store_true")
    tc.add_argument("--perm-create-domain",  action="store_true")
    tc.add_argument("--perm-delete-domain",  action="store_true")
    tc.add_argument("--auto-policy",         action="store_true")
    tc.add_argument("--subnets",  help="Comma-separated allowed subnets (e.g. 10.0.0.0/8)")
    tc.add_argument("--max-unused", help="Max unused period — ISO 8601 duration (e.g. P90D)")

    td = tsub.add_parser("delete", help="Delete a token")
    td.add_argument("token_id", help="Token ID")

    # ── domain ───────────────────────────────────────────────────────────────
    dp = sub.add_parser("domain", help="Manage domains")
    dsub = dp.add_subparsers(dest="domain_cmd", metavar="ACTION")

    dsub.add_parser("list", help="List all domains")

    dca = dsub.add_parser("create", help="Register a domain")
    dca.add_argument("name", help="Domain name (e.g. example.dedyn.io)")

    dde = dsub.add_parser("delete", help="Delete a domain and all its records")
    dde.add_argument("name", help="Domain name")
    dde.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")

    # ── record ───────────────────────────────────────────────────────────────
    rp = sub.add_parser("record", help="Manage DNS records (RRsets)")
    rsub = rp.add_subparsers(dest="record_cmd", metavar="ACTION")

    rl = rsub.add_parser("list", help="List all RRsets for a domain")
    rl.add_argument("domain")

    ra = rsub.add_parser("add", help="Add a new RRset")
    ra.add_argument("domain")
    ra.add_argument("--subname", default="",  help="Subdomain label (blank = apex @)")
    ra.add_argument("--type",    dest="rtype", required=True, metavar="TYPE",
                    help="Record type (A, AAAA, CNAME, MX, TXT, ...)")
    ra.add_argument("--ttl",  type=int, default=3600, help="TTL in seconds (default: 3600)")
    ra.add_argument("--rdata", action="append", required=True, dest="rdata", metavar="VALUE",
                    help="Record value — repeat for multiple (e.g. --rdata 1.2.3.4)")

    re_ = rsub.add_parser("edit", help="Replace records in an existing RRset")
    re_.add_argument("domain")
    re_.add_argument("--subname", default="")
    re_.add_argument("--type",    dest="rtype", required=True, metavar="TYPE")
    re_.add_argument("--ttl",  type=int, default=3600)
    re_.add_argument("--rdata", action="append", required=True, dest="rdata", metavar="VALUE")

    rdel = rsub.add_parser("delete", help="Delete an RRset")
    rdel.add_argument("domain")
    rdel.add_argument("--subname", default="")
    rdel.add_argument("--type",    dest="rtype", required=True, metavar="TYPE")
    rdel.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")

    # ── ddns-add ──────────────────────────────────────────────────────────────
    da = sub.add_parser("ddns-add",
        help="Provision a DDNS token: set initial address records + create A/AAAA-only scoped key")
    da.add_argument("domain", help="Domain name (e.g. example.dedyn.io)")
    da.add_argument("--subname", default="", help="Subdomain label (blank = apex @)")
    da.add_argument("--ipv4",    metavar="ADDR", help="Initial IPv4 address for A record")
    da.add_argument("--ipv6",    metavar="ADDR", help="Initial IPv6 address for AAAA record")
    da.add_argument("--ttl",  type=int, default=3600)
    da.add_argument("--token-name", dest="token_name", metavar="NAME",
                    help="Name for the new token (default: <hostname>-ddns)")

    # ── cert-add ──────────────────────────────────────────────────────────────
    ca = sub.add_parser("cert-add",
        help="Provision a single-domain cert token: optional initial records + TXT-only scoped key")
    ca.add_argument("domain", help="Domain name")
    ca.add_argument("--subname", default="")
    ca.add_argument("--ipv4",  metavar="ADDR", help="Initial A record (set now, not in token)")
    ca.add_argument("--ipv6",  metavar="ADDR", help="Initial AAAA record (set now, not in token)")
    ca.add_argument("--cname", metavar="TARGET", help="Initial CNAME target (mutually exclusive with --ipv4/--ipv6)")
    ca.add_argument("--ttl",  type=int, default=3600)
    ca.add_argument("--token-name", dest="token_name", metavar="NAME",
                    help="Name for the new token (default: <hostname>-cert)")

    # ── cert-multi ────────────────────────────────────────────────────────────
    cm = sub.add_parser("cert-multi",
        help="Provision a multi-domain cert token: TXT-only scoped key, no address access")
    cm.add_argument("--entry", action="append", metavar="DOMAIN[:SUBNAME]", dest="entries",
                    required=True,
                    help="Domain entry — repeat for each hostname (e.g. --entry example.dedyn.io "
                         "--entry example.dedyn.io:www)")
    cm.add_argument("--token-name", dest="token_name", metavar="NAME", required=True,
                    help="Name for the new token")

    return p


def _print_table(headers: list[str], rows: list[list[str]]) -> None:
    try:
        from rich.table import Table
        from rich.console import Console
        t = Table(*headers, highlight=True)
        for r in rows:
            t.add_row(*r)
        Console().print(t)
    except ImportError:
        widths = [max(len(h), max((len(str(r[i])) for r in rows), default=0))
                  for i, h in enumerate(headers)]
        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        print(fmt.format(*headers))
        print("  ".join("-" * w for w in widths))
        for r in rows:
            print(fmt.format(*[str(c) for c in r]))


def _print_output(data: object, fmt: str,
                  headers: list[str] | None = None,
                  rows: list[list[str]] | None = None) -> None:
    """Unified output: table / json / yaml.  Falls back gracefully if deps absent."""
    if fmt == "yaml":
        if _yaml is not None:
            print(_yaml.dump(data, default_flow_style=False, allow_unicode=True,
                             sort_keys=False).rstrip())
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))
    elif fmt == "json":
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        if headers is not None and rows is not None:
            _print_table(headers, rows)
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))


def _require_token(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    # Precedence: --token flag > DESEC_TOKEN env var > desec.env file
    tok = args.token or os.environ.get("DESEC_TOKEN", "") or load_env().get("DESEC_TOKEN", "")
    if not tok:
        parser.error(
            "No API token found. Pass --token, set DESEC_TOKEN env var, "
            "or add DESEC_TOKEN to ~/.config/mech-goodies/desec.env"
        )
    return tok


def _run_cli(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    tok = _require_token(args, parser)
    fmt = args.output

    # ── token ─────────────────────────────────────────────────────────────
    if args.command == "token":
        if not args.token_cmd or args.token_cmd == "list":
            tokens = list_tokens(tok)
            _print_output(
                tokens, fmt,
                headers=["Name", "ID", "Manage?", "Create?", "Delete?", "Subnets"],
                rows=[
                    [
                        t.get("name") or "",
                        t.get("id", ""),
                        "yes" if t.get("perm_manage_tokens") else "no",
                        "yes" if t.get("perm_create_domain")  else "no",
                        "yes" if t.get("perm_delete_domain")  else "no",
                        ", ".join(t.get("allowed_subnets") or []) or "any",
                    ]
                    for t in tokens
                ],
            )

        elif args.token_cmd == "create":
            subnets = [s.strip() for s in (args.subnets or "").split(",") if s.strip()]
            result = create_token(
                tok, args.name,
                perm_manage_tokens=args.perm_manage_tokens,
                perm_create_domain=args.perm_create_domain,
                perm_delete_domain=args.perm_delete_domain,
                allowed_subnets=subnets,
                max_unused_period=args.max_unused or None,
                auto_policy=args.auto_policy,
            )
            if fmt in ("json", "yaml"):
                _print_output(result, fmt)
            else:
                secret = result.get("token", "(not returned)")
                print(f"Token created:  {result.get('name')}  ({result.get('id')})")
                print(f"Secret (copy now — shown once):  {secret}")

        elif args.token_cmd == "delete":
            delete_token(tok, args.token_id)
            print(f"Deleted token {args.token_id}")

        else:
            parser.parse_args(["token", "--help"])

    # ── domain ────────────────────────────────────────────────────────────
    elif args.command == "domain":
        if not args.domain_cmd or args.domain_cmd == "list":
            domains = list_domains(tok)
            _print_output(
                domains, fmt,
                headers=["Name", "Created", "Min TTL"],
                rows=[
                    [d.get("name", ""), (d.get("created") or "")[:10],
                     str(d.get("minimum_ttl", ""))]
                    for d in domains
                ],
            )

        elif args.domain_cmd == "create":
            result = create_domain(tok, args.name)
            if fmt in ("json", "yaml"):
                _print_output(result, fmt)
            else:
                print(f"Domain registered: {result.get('name')}")

        elif args.domain_cmd == "delete":
            if not args.yes:
                confirm = input(f"Delete domain '{args.name}' and ALL its records? [y/N] ")
                if confirm.lower() not in ("y", "yes"):
                    print("Aborted.")
                    return
            delete_domain(tok, args.name)
            print(f"Deleted domain {args.name}")

        else:
            parser.parse_args(["domain", "--help"])

    # ── record ────────────────────────────────────────────────────────────
    elif args.command == "record":
        if not args.record_cmd or args.record_cmd == "list":
            rrsets = list_rrsets(tok, args.domain)
            _print_output(
                rrsets, fmt,
                headers=["Subname", "Type", "TTL", "Records"],
                rows=[
                    [
                        rr.get("subname") or "@",
                        rr.get("type", ""),
                        str(rr.get("ttl", "")),
                        "; ".join(rr.get("records", [])),
                    ]
                    for rr in rrsets
                ],
            )

        elif args.record_cmd == "add":
            result = create_rrset(tok, args.domain, args.subname,
                                  args.rtype, args.ttl, args.rdata)
            if fmt in ("json", "yaml"):
                _print_output(result, fmt)
            else:
                sub = result.get("subname") or "@"
                print(f"Created {sub} {result.get('type')} (TTL {result.get('ttl')})")

        elif args.record_cmd == "edit":
            result = update_rrset(tok, args.domain, args.subname,
                                  args.rtype, args.ttl, args.rdata)
            if fmt in ("json", "yaml"):
                _print_output(result, fmt)
            else:
                sub = result.get("subname") or "@"
                print(f"Updated {sub} {result.get('type')} (TTL {result.get('ttl')})")

        elif args.record_cmd == "delete":
            if not args.yes:
                sub = args.subname or "@"
                confirm = input(f"Delete {sub} {args.rtype} from '{args.domain}'? [y/N] ")
                if confirm.lower() not in ("y", "yes"):
                    print("Aborted.")
                    return
            delete_rrset(tok, args.domain, args.subname, args.rtype)
            sub = args.subname or "@"
            print(f"Deleted {sub} {args.rtype} from {args.domain}")

        else:
            parser.parse_args(["record", "--help"])

    # ── ddns-add ──────────────────────────────────────────────────────────
    elif args.command == "ddns-add":
        host = f"{args.subname}.{args.domain}" if args.subname else args.domain
        name = args.token_name or f"{host}-ddns"
        result = provision_ddns_token(
            tok, name, args.domain, args.subname,
            args.ipv4 or None, args.ipv6 or None, args.ttl,
        )
        if fmt in ("json", "yaml"):
            _print_output(result, fmt)
        else:
            secret = result.get("token", "(not returned)")
            print(f"DDNS token created: {result.get('name')}  ({result.get('id')})")
            print(f"Hostname:           {host}")
            print(f"Permitted records:  A, AAAA  (write-only for {host})")
            print(f"Secret (copy now):  {secret}")

    # ── cert-add ──────────────────────────────────────────────────────────
    elif args.command == "cert-add":
        if args.cname and (args.ipv4 or args.ipv6):
            parser.error("--cname is mutually exclusive with --ipv4 / --ipv6")
        host = f"{args.subname}.{args.domain}" if args.subname else args.domain
        name = args.token_name or f"{host}-cert"
        result = provision_cert_token(
            tok, name, args.domain, args.subname,
            args.ipv4 or None, args.ipv6 or None, args.cname or None, args.ttl,
        )
        acme = f"{_acme_subname(args.subname)}.{args.domain}."
        if fmt in ("json", "yaml"):
            _print_output(result, fmt)
        else:
            secret = result.get("token", "(not returned)")
            print(f"Cert token created: {result.get('name')}  ({result.get('id')})")
            print(f"Hostname:           {host}")
            print(f"ACME challenge at:  {acme}  (TXT write-only)")
            print(f"Secret (copy now):  {secret}")

    # ── cert-multi ────────────────────────────────────────────────────────
    elif args.command == "cert-multi":
        entries: list[tuple[str, str]] = []
        for raw in args.entries:
            if ":" in raw:
                domain, subname = raw.split(":", 1)
            else:
                domain, subname = raw, ""
            entries.append((domain.strip(), subname.strip()))
        result = provision_cert_multi_token(tok, args.token_name, entries)
        if fmt in ("json", "yaml"):
            _print_output(result, fmt)
        else:
            secret = result.get("token", "(not returned)")
            print(f"Multi-cert token: {result.get('name')}  ({result.get('id')})")
            for domain, subname in entries:
                acme = f"{_acme_subname(subname)}.{domain}."
                print(f"  ACME challenge:  {acme}  (TXT write-only)")
            print(f"Secret (copy now): {secret}")

    else:
        parser.print_help()


if __name__ == "__main__":
    _parser = _build_cli_parser()
    _args = _parser.parse_args()

    # No subcommand (or --ui) → launch TUI
    if _args.ui or _args.command is None:
        try:
            import textual  # noqa: F401
        except ImportError:
            print("Textual is required for the TUI. Run:  pip install textual httpx")
            sys.exit(1)
        DeSECApp().run()
    else:
        try:
            _run_cli(_args, _parser)
        except httpx.HTTPStatusError as _e:
            print(f"API error {_e.response.status_code}: {_e.response.text[:300]}", file=sys.stderr)
            sys.exit(1)
        except Exception as _e:
            print(f"Error: {_e}", file=sys.stderr)
            sys.exit(1)
