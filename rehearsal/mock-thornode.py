#!/usr/bin/env python3
"""Minimal mock THORNode for the halt drill (docs/runbooks/halt-watchdog.md).

Serves `GET /thorchain/inbound_addresses` with a single BTC entry whose
`halted` flag is true iff the halt-flag file exists -- so the drill toggles
the halt with `touch` / `rm`, with no restart and no control endpoint.

Usage: mock-thornode.py <port> [halt_flag_file]
  halt_flag_file defaults to $XINDEX_REHEARSAL_DIR/thor-halt.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18551
REHEARSAL_DIR = os.environ.get("XINDEX_REHEARSAL_DIR", "/tmp/xindex-rehearsal")
HALT_FLAG = sys.argv[2] if len(sys.argv) > 2 else os.path.join(REHEARSAL_DIR, "thor-halt")


def inbound_addresses() -> bytes:
    """Return the inbound_addresses body; `halted` tracks the flag file."""
    halted = os.path.exists(HALT_FLAG)
    return json.dumps(
        [
            {
                "chain": "BTC",
                "pub_key": "thorpub1mockvault",
                "address": "bc1qmockvaultaddressforthehaltdrill",
                "halted": halted,
                "global_trading_paused": False,
                "chain_trading_paused": False,
                "chain_lp_actions_paused": False,
            }
        ]
    ).encode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (name mandated by BaseHTTPRequestHandler)
        if self.path != "/thorchain/inbound_addresses":
            self.send_response(404)
            self.end_headers()
            return
        body = inbound_addresses()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        """Silence per-request stderr logging."""


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
