# tailscale.py

Tailscale ACL policy manager and device tagger.  Pulls your tailnet's ACL policy, validates and fixes it, manages service/grant tags, and pushes changes back.

## Requirements

```bash
pip install json5     # for HuJSON/JSON5 policy files
# httpx is used for the Tailscale API
pip install httpx
```

Set `TS_API_KEY` (or `TAILSCALE_API_KEY`) and `TS_TAILNET` in your environment or in `~/.config/mech-goodies/tailscale.env`.

## Usage

```bash
# Pull current policy from the API, validate, and show a diff
python tailscale.py --pull --validate

# Read a local policy file, validate it, and show what --fix would change
python tailscale.py --in policy.json --validate --dry-run

# Apply fixes and push
python tailscale.py --pull --fix --push

# Add services (creates tag:service-<name> + global grant)
python tailscale.py --pull --add service sonarr=8989/tcp radarr=7878 jellyfin=8096,8920 --fix --push

# Add host-specific grants (tag:grant-<service>-<clientTag>)
python tailscale.py --pull --add grant media-host-1=owner-alice:sonarr,radarr --fix --push

# Interactive shell (avoids re-invoking the script for each operation)
python tailscale.py --shell
```

## Key flags

| Flag | Effect |
|---|---|
| `--pull` | Fetch the live ACL policy from the Tailscale API |
| `--in FILE` | Read policy from a local JSON/JSON5 file instead |
| `--out` | Write before/after snapshots to `~/.config/mech-goodies/tailscale/logs/` |
| `--validate` | Run read-only checks (also runs by default) |
| `--validate-remote` | Call Tailscale `/acl/validate` endpoint (read-only) |
| `--fix` | Apply fixes to the policy and/or device tags |
| `--push` | Push updated policy to the tailnet (only if validation passes) |
| `--dry-run` | Print intended actions without making any changes |
| `--shell` | Interactive REPL |
| `--add service NAME=PORTS ...` | Define a new service and its global grant |
| `--add grant HOST=TAG:SVCS ...` | Add host-specific grants for a client tag |

## Port spec syntax

```
8989           → tcp:8989 + udp:8989
8989/tcp       → tcp only
53/udp         → udp only
80-443         → tcp:80-443 + udp:80-443
8096,8920      → two separate ports (both tcp+udp)
tcp:443,udp:53 → explicit capability selectors
```

## Safety rules

- Device tag operations do **not** require `--fix`, except:
  - Removing an existing `owner-*` tag
  - Replacing/normalising an existing `owner-*` tag
  - These additionally require `--fix --allow-owner-change`
- Adding a first `owner-*` tag to a device that has none is always allowed without `--fix`.

## Services model

A service is a `tag:service-<name>` with a global grant:

```
src ["*"] → dst ["tag:service-sonarr"] with ip ["tcp:8989"]
```

Tagging a host with `tag:service-sonarr` means it runs Sonarr and is reachable on port 8989 by whoever the grant allows.

## Grant tags model

```
tag:grant-sonarr-owner-alice
```

Gives hosts tagged `owner-alice` access to `sonarr` on the tagged machine.  The policy grant is:

```
src ["tag:owner-alice"] → dst ["tag:grant-sonarr-owner-alice"] with ip ["tcp:8989"]
```
