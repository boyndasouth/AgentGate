"""A tiny fake upstream API for local tests (Day 12). Stdlib only. Never deploy it.

It stands in for the real APIs an HTTP tool would call, so tests can check what the broker
forwards without any outside service. Every endpoint except /health requires
`Authorization: Bearer $UPSTREAM_MOCK_TOKEN` (the credential the broker holds); without it: 401.

  GET  /health                      {"ok": true}
  ANY  /echo[/...]                  echoes the method, path, query, HEADERS and body back
                                    (an upstream that leaks its request: the broker must scrub
                                    the credential before the agent sees it)
  PATCH /crm/tickets/{id}           fake CRM: {"ticket": id, "updated": {...}}
  POST /email/send                  fake mail: {"status": "queued", "id": ...}
  POST /payments                    fake payments: {"status": "completed", "tx_id": ...}
  GET  /redirect                    302 to http://169.254.169.254/ (a redirect must never be followed)
  GET  /slow?s=N                    waits N seconds (timeouts)
  GET  /big?kb=N                    N KiB of text (size cap)
  GET  /requests                    the last 50 requests it received (not counting /requests and /health), for tests (no secrets: the
                                    Authorization header is reduced to "ok" / "wrong" / "missing")

  python deploy/mock-upstream/server.py [port]      (compose: service `mock-upstream`, port 9090)
"""

from __future__ import annotations

import hmac
import json
import os
import sys
import time
import urllib.parse
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("UPSTREAM_MOCK_TOKEN", "")
SEEN: deque = deque(maxlen=50)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mock-upstream/1"

    def log_message(self, fmt: str, *args) -> None:   # quiet; /requests has what tests need
        pass

    def _send(self, status: int, body, headers: dict | None = None) -> None:
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain" if isinstance(body, bytes) else "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self) -> None:
        url = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            body = raw.decode(errors="replace")
        auth = self.headers.get("Authorization")
        auth_state = "missing" if auth is None else (
            "ok" if TOKEN and hmac.compare_digest(auth, f"Bearer {TOKEN}") else "wrong")
        if url.path not in ("/requests", "/health"):
            SEEN.append({"method": self.command, "path": url.path, "query": url.query, "auth": auth_state,
                         "host": self.headers.get("Host"), "body": body})

        if url.path == "/health":
            return self._send(200, {"ok": True})
        if url.path == "/requests":
            return self._send(200, list(SEEN))
        if auth_state != "ok":
            return self._send(401, {"error": "unauthorized"})

        if url.path == "/echo" or url.path.startswith("/echo/"):
            return self._send(200, {"method": self.command, "path": url.path, "query": url.query,
                                    "headers": dict(self.headers.items()), "body": body})
        parts = url.path.strip("/").split("/")
        if self.command == "PATCH" and len(parts) == 3 and parts[:2] == ["crm", "tickets"]:
            return self._send(200, {"ticket": urllib.parse.unquote(parts[2]), "updated": body})
        if self.command == "POST" and url.path == "/email/send":
            return self._send(200, {"status": "queued", "id": str(uuid.uuid4())})
        if self.command == "POST" and url.path == "/payments":
            return self._send(200, {"status": "completed", "tx_id": f"tx_{uuid.uuid4().hex[:12]}"})
        if url.path == "/redirect":
            return self._send(302, {"moved": True}, {"Location": "http://169.254.169.254/latest/meta-data/"})
        q = dict(urllib.parse.parse_qsl(url.query))
        if url.path == "/slow":
            time.sleep(min(float(q.get("s", "5")), 60))
            return self._send(200, {"slept": True})
        if url.path == "/big":
            return self._send(200, b"x" * (1024 * min(int(q.get("kb", "512")), 8192)))
        return self._send(404, {"error": "not found"})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle


if __name__ == "__main__":
    if not TOKEN:
        sys.exit("set UPSTREAM_MOCK_TOKEN")
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9090
    print(f"mock-upstream on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
