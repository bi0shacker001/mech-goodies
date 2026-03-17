# mech-goodies

Personal collection of homelab tooling and automation scripts.

## Programs

Full applications shipped as installable packages or standalone executables.

| Program | Description |
|---|---|
| [programs/moxmanager](programs/moxmanager/) | Extended web interface for Proxmox VE — full management dashboard + connector agent |
| [programs/desec](programs/desec/) | deSEC DNS manager — TUI, CLI, and optional Qt GUI |

## Python scripts

Standalone scripts for day-to-day admin tasks.  Each runs as a single file (or from its directory) with no installation needed beyond `pip install` of its dependencies.

| Script | Description |
|---|---|
| [python-scripts/desec](python-scripts/desec/) | deSEC DNS API token and record manager (legacy monolithic version) |
| [python-scripts/tailscale](python-scripts/tailscale/) | Tailscale ACL policy manager and device tagger |
| [python-scripts/jellyfin-precache](python-scripts/jellyfin-precache/) | Pre-warms rclone VFS cache on Jellyfin playback start |

## Layout

```
programs/          Full applications (each is a git submodule with its own repo)
python-scripts/    Standalone single-file scripts
```

## Config convention

All tools store their config under `~/.config/mech-goodies/<tool>.env`.
