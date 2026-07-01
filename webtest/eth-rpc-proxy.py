#!/usr/bin/env python3
"""Minimal CORS JSON-RPC proxy: forwards browser POSTs to an upstream RPC and
adds permissive CORS headers (public Sepolia RPCs don't send them, so a browser
dApp can't call them directly). Usage: eth-rpc-proxy.py <port> <upstream_url>.
DEV / TESTNET ONLY."""
import sys
import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
UPSTREAM = sys.argv[2]


class Handler(BaseHTTPRequestHandler):
    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "content-type")

    def do_OPTIONS(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self._cors()
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n)
        try:
            req = urllib.request.Request(
                UPSTREAM,
                data=body,
                headers={
                    "content-type": "application/json",
                    # publicnode (Cloudflare) 403s the default Python-urllib UA.
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) xindex-webtest",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as r:
                out = r.read()
            code = 200
        except Exception as exc:  # noqa: BLE001 — proxy must answer, never crash
            out = json.dumps({"jsonrpc": "2.0", "error": {"code": -32000, "message": str(exc)}}).encode()
            code = 502
        self.send_response(code)
        self._cors()
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *_args) -> None:  # silence per-request logging
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
