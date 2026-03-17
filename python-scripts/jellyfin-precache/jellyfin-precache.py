#!/usr/bin/env python3
import argparse
import json
import os
import threading
import urllib.request
from queue import Queue
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

JF_URL = os.environ.get("JF_URL", "http://jellyfin:8096").rstrip("/")
JF_TOKEN = os.environ.get("JF_TOKEN", "").strip()

# How many files to prefetch at once
WORKERS = int(os.environ.get("PREFETCH_WORKERS", "2"))

# Optional: max queue depth (prevents infinite backlog)
MAX_QUEUE = int(os.environ.get("PREFETCH_MAX_QUEUE", "50"))

q: Queue[str] = Queue(maxsize=MAX_QUEUE)
inflight = set()
inflight_lock = threading.Lock()


def jellyfin_get_item_path(user_id: str, item_id: str) -> str | None:
    url = f"{JF_URL}/Users/{user_id}/Items/{item_id}"
    req = urllib.request.Request(url)

    # REQUIRED Jellyfin auth header format
    req.add_header(
        "Authorization",
        f'MediaBrowser Client="Jellyfin Web", Token="{JF_TOKEN}"'
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("Path")


def prefetch_file(path: str):
    try:
        # Read entire file to /dev/null-equivalent to fill rclone VFS cache
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)  # 1 MiB blocks
                if not chunk:
                    break
        print(f"[prefetch] finished: {path}", flush=True)
    except Exception as e:
        print(f"[prefetch] error reading {path}: {e}", flush=True)


def enqueue(path: str) -> bool:
    with inflight_lock:
        if path in inflight:
            return False
        inflight.add(path)

    try:
        q.put_nowait(path)
        return True
    except Exception:
        # Queue full
        with inflight_lock:
            inflight.discard(path)
        return False


def worker_loop(worker_id: int):
    while True:
        path = q.get()
        try:
            print(f"[prefetch] worker {worker_id} starting: {path}", flush=True)
            prefetch_file(path)
        finally:
            with inflight_lock:
                inflight.discard(path)
            q.task_done()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))

            if payload.get("type") != "PlaybackStart":
                self.send_response(204)
                self.end_headers()
                return

            user_id = payload.get("userId")
            item_id = payload.get("itemId")
            if not user_id or not item_id:
                self.send_response(400)
                self.end_headers()
                return

            path = jellyfin_get_item_path(user_id, item_id)
            if not path:
                self.send_response(404)
                self.end_headers()
                return

            ok = enqueue(path)
            if ok:
                self.send_response(202)
            else:
                # Either already queued/inflight, or queue is full
                self.send_response(202)
            self.end_headers()

        except Exception as e:
            print(f"[prefetch] webhook error: {e}", flush=True)
            self.send_response(500)
            self.end_headers()

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--local",
        action="store_true",
        help="Bind to 127.0.0.1 instead of 0.0.0.0"
    )
    args = parser.parse_args()

    if not JF_TOKEN:
        print("[prefetch] ERROR: set JF_TOKEN to a Jellyfin API key", flush=True)
        raise SystemExit(1)

    bind_addr = "127.0.0.1" if args.local else "0.0.0.0"

    # Start worker threads
    for i in range(WORKERS):
        t = threading.Thread(target=worker_loop, args=(i + 1,), daemon=True)
        t.start()

    print(f"[prefetch] listening on {bind_addr}:9109 with {WORKERS} workers", flush=True)
    server = ThreadingHTTPServer((bind_addr, 9109), Handler)
    server.serve_forever()
