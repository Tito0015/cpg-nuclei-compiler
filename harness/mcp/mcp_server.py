"""Stdlib dummy MCP HTTP server for closed-loop Nuclei harness (unauth tools/list)."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS_LIST_OK = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "tools": [
            {
                "name": "read_file",
                "description": "read a file",
                "inputSchema": {"type": "object"},
            }
        ]
    },
}


def json_rpc_error(code: int, message: str, req_id: int | str | None = None) -> bytes:
    body = {
        "jsonrpc": "2.0",
        "id": req_id if req_id is not None else 1,
        "error": {"code": code, "message": message},
    }
    return json.dumps(body).encode("utf-8")


class McpHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/health", "/"):
            body = b"mcp-fixture-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/mcp", "/", "/messages", "/sse"):
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        req_id: int | str | None = 1
        try:
            payload = json.loads(raw.decode("utf-8") if raw else "{}")
            req_id = payload.get("id", 1)
            method = payload.get("method")
        except (json.JSONDecodeError, UnicodeDecodeError):
            err = json_rpc_error(-32600, "Invalid Request", req_id)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err)))
            self.end_headers()
            self.wfile.write(err)
            return

        if method == "tools/list":
            body = json.dumps(TOOLS_LIST_OK).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        err = json_rpc_error(-32600, "Invalid Request", req_id)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(err)))
        self.end_headers()
        self.wfile.write(err)


def main() -> int:
    parser = argparse.ArgumentParser(description="CPG-Nuclei MCP harness fixture")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8265)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), McpHandler)
    print(f"mcp fixture listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
