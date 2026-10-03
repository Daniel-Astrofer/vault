#!/usr/bin/env python3
"""Real binary/mTLS loopback test; no Vault runtime, signer or production keys."""
import http.server
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / "target/debug/kerosene-vault"


def main():
    if not BINARY.is_file():
        raise SystemExit("Build kerosene-vault-app before running this test")
    with tempfile.TemporaryDirectory(prefix="cell-health-mtls-") as directory:
        root = Path(directory)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=root, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)

        for name in ("server", "client", "wrong"):
            openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=Synthetic Test CA", "-keyout", name + "-ca.key", "-out", name + "-ca.crt",
                    "-addext", "basicConstraints=critical,CA:TRUE")
            openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                    "-keyout", name + ".key", "-out", name + ".csr",
                    "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE",
                    "-addext", "extendedKeyUsage=" + ("serverAuth" if name == "server" else "clientAuth"))
            openssl("x509", "-req", "-in", name + ".csr", "-CA", name + "-ca.crt",
                    "-CAkey", name + "-ca.key", "-CAcreateserial", "-days", "1",
                    "-copy_extensions", "copy", "-out", name + ".crt")

        class Handler(http.server.BaseHTTPRequestHandler):
            body = b'{"local_ready":true,"financial_ready":false}'
            status = 200
            calls = 0

            def do_GET(self):
                type(self).calls += 1
                self.send_response(type(self).status)
                self.send_header("Content-Length", str(len(type(self).body)))
                self.send_header("Location", "https://localhost/v1/health")
                self.end_headers()
                self.wfile.write(type(self).body)

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "server.crt", root / "server.key")
        context.load_verify_locations(root / "client-ca.crt")
        context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        environment = {"PATH": os.defpath,
            "VAULT_HEALTH_PROBE_URL": f"https://localhost:{server.server_port}/v1/health",
            "VAULT_TLS_CLIENT_CERT_PATH": str(root / "client.crt"),
            "VAULT_TLS_CLIENT_KEY_PATH": str(root / "client.key"),
            "VAULT_TLS_CLIENT_CA_PATH": str(root / "server-ca.crt")}

        def probe(expected, changes=None):
            result = subprocess.run([str(BINARY), "--health-probe"], env={**environment, **(changes or {})},
                                    capture_output=True, timeout=8)
            assert result.returncode == expected, (expected, result.returncode, result.stderr)
            assert not result.stdout
            assert result.stderr == (b"" if expected == 0 else b"Vault authenticated local health probe failed\n")

        try:
            probe(0)
            probe(1, {"VAULT_TLS_CLIENT_CA_PATH": str(root / "wrong-ca.crt")})
            probe(1, {"VAULT_HEALTH_PROBE_URL": f"https://wrong.example:{server.server_port}/v1/health"})
            probe(1, {"VAULT_TLS_CLIENT_CERT_PATH": str(root / "wrong.crt"),
                      "VAULT_TLS_CLIENT_KEY_PATH": str(root / "wrong.key")})
            Handler.body = b'{"local_ready":false}'
            probe(1)
            Handler.body = b'{"local_ready":false,"local_ready":true}'
            probe(1)
            Handler.body = b"x" * 4097
            probe(1)
            Handler.body = b'{"local_ready":true}'
            Handler.status = 302
            before = Handler.calls
            probe(1)
            assert Handler.calls == before + 1, "probe followed a redirect"
            print("PASS: actual Vault binary: mTLS success, wrong CA/hostname/client rejection, readiness, duplicates, size and redirect checks")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
