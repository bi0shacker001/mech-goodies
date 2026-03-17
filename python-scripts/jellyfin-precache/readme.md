# jellyfin-precache

Listens for Jellyfin `PlaybackStart` webhooks and immediately reads the target media file in full, populating the rclone VFS cache before the user's stream gets there.

## How it works

1. Jellyfin fires a webhook on playback start
2. The script receives the POST, extracts `userId` and `itemId` from the payload
3. It calls the Jellyfin API to resolve the item's file path
4. The file is read sequentially in 1 MiB chunks, forcing rclone VFS to cache it
5. Duplicate requests for the same path are deduplicated — concurrent reads are capped by `PREFETCH_WORKERS`

## Requirements

- Python 3.10+ (uses `str | None` union syntax)
- Jellyfin with the [Webhook plugin](https://github.com/jellyfin/jellyfin-plugin-webhook) installed
- rclone VFS mount accessible at the same paths Jellyfin uses

## Setup

```bash
mkdir -p /opt/jellyfin-precache
cp jellyfin-precache.py /opt/jellyfin-precache/
chmod +x /opt/jellyfin-precache/jellyfin-precache.py
cp jellyfin-precache.env /opt/jellyfin-precache/
nano /opt/jellyfin-precache/jellyfin-precache.env
```

## Configuration

Edit `/opt/jellyfin-precache/jellyfin-precache.env`:

```env
JF_URL=http://jellyfin:8096       # Jellyfin base URL reachable from this host
JF_TOKEN=your_api_key_here        # Jellyfin API key (Dashboard → API Keys)
PREFETCH_WORKERS=2                # Concurrent file reads
PREFETCH_MAX_QUEUE=50             # Max queued items before new requests are dropped
```

All variables are read at startup. Restart the service after changes.

## Running

### systemd — local mode (bind 127.0.0.1)

Use when Jellyfin and this script are on the same host.

```bash
cp jellyfin-precache-local.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now jellyfin-precache-local
```

### systemd — remote mode (bind 0.0.0.0)

Use when the webhook originates from another host or container.

```bash
cp jellyfin-precache-remote.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now jellyfin-precache-remote
```

### Docker Compose

Adjust the media volume mount to match your rclone VFS mount path, then:

```bash
docker compose up -d
```

## Jellyfin webhook configuration

Dashboard → Webhooks → Add Generic Destination:

- **URL:** `http://<host>:9109`
- **Notification Type:** Playback Start only
- **Send all properties:** enabled

## Testing

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:9109 \
  -H "Content-Type: application/json" \
  -d '{"type":"PlaybackStart","userId":"<userId>","itemId":"<itemId>"}'
```

Expected response: `202`. Watch logs with `journalctl -u jellyfin-precache-local -f`.

## Port

`9109` (hardcoded)