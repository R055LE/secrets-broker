#!/usr/bin/env python3
"""Temporary Serve identity check for ADR-0022. Run from a reviewed git object."""

import http.server
import json
import os
import socket
import socketserver
import struct


SOCKET = "/run/secrets-broker-identity-probe.sock"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/identity":
            peer = self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack("3i", peer)
            body = json.dumps(
                {
                    "peer_uid": uid,
                    "login_headers": self.headers.get_all("Tailscale-User-Login", []),
                }
            ).encode()
            kind = "application/json"
        elif self.path == "/":
            body = b'''<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
<h1>Temporary identity check</h1>
<p>Normal request:</p><pre id="normal">loading</pre>
<button id="forge">Send forged identity header</button><pre id="forged"></pre>
<script>
async function show(id, headers) {
  const response = await fetch('/identity', {headers});
  document.getElementById(id).textContent = await response.text();
}
show('normal', {});
document.getElementById('forge').onclick = () =>
  show('forged', {'Tailscale-User-Login': 'forged@example.invalid'});
</script>'''
            kind = "text/html; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    if os.path.lexists(SOCKET):
        raise SystemExit("Probe socket already exists")
    os.umask(0o077)
    try:
        with socketserver.UnixStreamServer(SOCKET, Handler) as server:
            os.chmod(SOCKET, 0o600)
            print("Probe ready", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    finally:
        if os.path.exists(SOCKET):
            os.unlink(SOCKET)


if __name__ == "__main__":
    main()
