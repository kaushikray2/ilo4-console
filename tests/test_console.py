"""Unit tests for the iLO 4 Console backend (app/server.py).

Runs against a mock iLO 4: an in-process HTTPS server on 127.0.0.1:443
(the Redfish client hardcodes port 443, so the suite needs permission
to bind it - on Linux run with sudo, or grant CAP_NET_BIND_SERVICE):

    sudo python3 -m unittest discover -s tests -v

If something already occupies port 443 on the host, run just the
client-session class inside a private network namespace instead:

    sudo unshare -n bash -c 'ip link set lo up; python3 -m unittest test_console.TestClientSessions'

Stdlib only, like the app itself. No real iLO is ever contacted: every
server record in these tests points at 127.0.0.1.
"""
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app"))

TEST_DATA = tempfile.mkdtemp(prefix="ilo-test-data-")
os.environ["ILO_DATA_DIR"] = TEST_DATA

import server as ilo  # noqa: E402

# ---------------- mock iLO ----------------

CERT = os.path.join(tempfile.gettempdir(), "ilo-mock-cert.pem")
KEYF = os.path.join(tempfile.gettempdir(), "ilo-mock-key.pem")


class MockState:
    def __init__(self):
        self.sessions = {}        # token -> session path
        self.logins = 0
        self.reset_posts = 0
        self.deletes = 0
        self.drop_after_next = False
        self.hang_reset = False
        self.slow_s = 0
        self.fetched_entries = []
        self.entry_count = 35


ST = MockState()


class MockIlo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, code, obj=None, extra=None):
        raw = json.dumps(obj).encode() if obj is not None else b""
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if raw:
                self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass
        if ST.drop_after_next:
            ST.drop_after_next = False
            self.close_connection = True

    def _authed(self):
        return self.headers.get("X-Auth-Token") in ST.sessions

    def do_POST(self):
        self._body()
        if self.path.rstrip("/") == "/redfish/v1/SessionService/Sessions":
            ST.logins += 1
            tok = f"tok-{ST.logins}"
            path = f"/redfish/v1/SessionService/Sessions/{ST.logins}"
            ST.sessions[tok] = path
            self._send(201, {"UserName": "Administrator"},
                       {"X-Auth-Token": tok, "Location": f"https://127.0.0.1{path}"})
            return
        if self.path == "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset":
            if not self._authed():
                self._send(401, {})
                return
            ST.reset_posts += 1
            if ST.hang_reset:
                time.sleep(6)  # action accepted, response never arrives in time
            self._send(200, {})
            return
        self._send(404, {})

    def do_GET(self):
        if self.path == "/redfish/v1/SessionService/Sessions":
            if not self._authed():
                self._send(401, {})
                return
            self._send(200, {"Items": [{"UserName": "Administrator"} for _ in ST.sessions]})
            return
        if not self._authed():
            self._send(401, {})
            return
        if self.path == "/redfish/v1/Systems/1":
            if ST.slow_s:
                time.sleep(ST.slow_s)
            self._send(200, {"PowerState": "On", "Status": {"Health": "OK"}})
            return
        if self.path == "/redfish/v1/Managers/1/LogServices/IEL/Entries":
            members = [{"@odata.id": f"/redfish/v1/Managers/1/LogServices/IEL/Entries/{i}"}
                       for i in range(1, ST.entry_count + 1)]
            self._send(200, {"Items": [], "Members": members,
                             "Members@odata.count": ST.entry_count})
            return
        if self.path.startswith("/redfish/v1/Managers/1/LogServices/IEL/Entries/"):
            n = int(self.path.rsplit("/", 1)[1])
            ST.fetched_entries.append(n)
            self._send(200, {"RecordId": n, "Created": "2026-01-01T00:00:00Z",
                             "Severity": "OK", "Message": f"entry {n}"})
            return
        self._send(404, {})

    def do_DELETE(self):
        if self.path.startswith("/redfish/v1/SessionService/Sessions/"):
            ST.deletes += 1
            for tok, p in list(ST.sessions.items()):
                if p == self.path:
                    del ST.sessions[tok]
            self._send(200, {})
            return
        self._send(404, {})


def start_mock():
    if not (os.path.exists(CERT) and os.path.exists(KEYF)):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-keyout", KEYF, "-out", CERT, "-days", "1", "-nodes",
                        "-subj", "/CN=localhost"], check=True, capture_output=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 443), MockIlo)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEYF)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


REC = {"id": "testserver1", "host": "127.0.0.1", "name": "Mock",
       "username": "Administrator", "password": "ilo-pw"}


def fresh_state():
    ST.__init__()
    with ilo._CLIENTS_LOCK:
        ilo._CLIENTS.clear()


# ---------------- Redfish client behaviour ----------------

class TestClientSessions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_mock()

    def setUp(self):
        fresh_state()

    def test_single_login_survives_dropped_connection(self):
        body, _ = ilo.redfish(REC, "GET", "/redfish/v1/Systems/1")
        self.assertEqual(body["PowerState"], "On")
        ST.drop_after_next = True
        ilo.redfish(REC, "GET", "/redfish/v1/Systems/1")   # this reply closes the socket
        body, _ = ilo.redfish(REC, "GET", "/redfish/v1/Systems/1")  # must recover, same token
        self.assertEqual(body["PowerState"], "On")
        self.assertEqual(ST.logins, 1)  # the whole point of v0.02: no new session

    def test_relogin_once_on_401(self):
        ilo.redfish(REC, "GET", "/redfish/v1/Systems/1")
        ST.sessions.clear()  # iLO forgot our session (e.g. iLO was reset)
        body, _ = ilo.redfish(REC, "GET", "/redfish/v1/Systems/1")
        self.assertEqual(body["PowerState"], "On")
        self.assertEqual(ST.logins, 2)

    def test_post_never_retried_when_response_lost(self):
        ilo.redfish(REC, "GET", "/redfish/v1/Systems/1")
        ST.hang_reset = True
        t0 = time.time()
        with self.assertRaises(RuntimeError) as cm:
            ilo.redfish(REC, "POST", "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
                        {"ResetType": "PushPowerButton"}, timeout=2)
        self.assertIn("may have taken effect", str(cm.exception))
        self.assertLess(time.time() - t0, 5)
        self.assertEqual(ST.reset_posts, 1)  # sent exactly once

    def test_close_session_deletes_on_ilo(self):
        ilo.redfish(REC, "GET", "/redfish/v1/Systems/1")
        self.assertEqual(len(ST.sessions), 1)
        ilo._client_for(REC).close_session()
        self.assertEqual(ST.deletes, 1)
        self.assertEqual(ST.sessions, {})

    def test_per_request_timeout_is_honored(self):
        ilo.redfish(REC, "GET", "/redfish/v1/Systems/1")
        ST.slow_s = 3
        t0 = time.time()
        try:
            with self.assertRaises(Exception):
                ilo.redfish(REC, "GET", "/redfish/v1/Systems/1", timeout=1)
        finally:
            ST.slow_s = 0
        # 4 attempts x ~1 s, not one 30 s wait (and before the fix this
        # call wrongly SUCCEEDED after 3 s on the fixed 30 s socket)
        self.assertLess(time.time() - t0, 9)

    def test_fetch_logs_fallback_is_newest_and_sequential(self):
        out = ilo.fetch_logs(REC)
        self.assertEqual(len(out), 30)
        self.assertEqual(out[0]["message"], "entry 35")
        self.assertEqual(sorted(ST.fetched_entries), list(range(6, 36)))


# ---------------- encryption key handling ----------------

class TestKeyHandling(unittest.TestCase):
    def test_key_with_whitespace_end_bytes_roundtrips(self):
        crafted = b"\x20" + bytes(range(1, 31)) + b"\x09"  # 32 bytes, ws at both ends
        self.assertEqual(len(crafted), 32)
        d = tempfile.mkdtemp(prefix="ilo-keytest-")
        with open(os.path.join(d, ".key"), "wb") as f:
            f.write(crafted)
        code = (
            "import sys; sys.path.insert(0, %r); import server as s;"
            "k = s._key(); assert k == %r, ('key changed', k);"
            "e = s.enc_secret('s3cret'); assert e.startswith('enc1:');"
            "assert s.dec_secret(e) == 's3cret'; print('KEYTEST-OK')"
        ) % (os.path.join(ROOT, "app"), crafted)
        env = dict(os.environ, ILO_DATA_DIR=d)
        r = subprocess.run([sys.executable, "-c", code], env=env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("KEYTEST-OK", r.stdout)


# ---------------- HTTP API: auth + registry ----------------

class TestApi(unittest.TestCase):
    cookie = None
    sid = None

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), ilo.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    def req(self, method, path, body=None, cookie=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(url, data=data, method=method)
        if data:
            r.add_header("Content-Type", "application/json")
        if cookie:
            r.add_header("Cookie", cookie)
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"{}"), resp.headers.get("Set-Cookie")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}"), e.headers.get("Set-Cookie")

    def test_1_unauthenticated(self):
        code, _, _ = self.req("GET", "/api/servers")
        self.assertEqual(code, 401)
        code, body, _ = self.req("GET", "/api/health")
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])

    def test_2_setup_then_login(self):
        code, _, sc = self.req("POST", "/api/auth/setup", {"password": "test-pass-123"})
        self.assertEqual(code, 200)
        self.assertIn("ilo_session=", sc)
        type(self).cookie = sc.split(";")[0]
        code, _, _ = self.req("POST", "/api/auth/setup", {"password": "another-pass"})
        self.assertEqual(code, 403)  # setup only ever happens once
        code, _, _ = self.req("POST", "/api/auth/login", {"password": "wrong-pass"})
        self.assertEqual(code, 401)
        code, _, sc = self.req("POST", "/api/auth/login", {"password": "test-pass-123"})
        self.assertEqual(code, 200)
        type(self).cookie = sc.split(";")[0]

    def test_3_add_server_encrypts_password(self):
        code, body, _ = self.req("POST", "/api/servers",
                                 {"name": "Mock", "host": "127.0.0.1",
                                  "username": "Administrator", "password": "ilo-pw"},
                                 cookie=self.cookie)
        self.assertEqual(code, 201)
        type(self).sid = body["id"]
        with open(os.path.join(TEST_DATA, "servers.json")) as f:
            raw = f.read()
        self.assertNotIn("ilo-pw", raw)          # never stored in plain text
        self.assertIn("enc1:", raw)
        saved = [s for s in ilo.load_servers() if s["id"] == self.sid]
        self.assertEqual(saved[0]["password"], "ilo-pw")  # and decrypts back

    def test_4_put_host_change_evicts_client(self):
        rec = [s for s in ilo.load_servers() if s["id"] == self.sid][0]
        ilo._client_for(rec)  # materialize a client bound to the old host
        self.assertTrue(any(k[0] == self.sid and k[1] == "127.0.0.1"
                            for k in ilo._CLIENTS))
        code, _, _ = self.req("PUT", f"/api/servers/{self.sid}",
                              {"host": "127.0.0.2"}, cookie=self.cookie)
        self.assertEqual(code, 200)
        self.assertFalse(any(k[0] == self.sid and k[1] == "127.0.0.1"
                             for k in ilo._CLIENTS))  # stale client evicted
        rec2 = [s for s in ilo.load_servers() if s["id"] == self.sid][0]
        self.assertEqual(ilo._client_for(rec2).host, "127.0.0.2")

    def test_5_delete_evicts_client(self):
        code, _, _ = self.req("DELETE", f"/api/servers/{self.sid}", cookie=self.cookie)
        self.assertEqual(code, 200)
        self.assertFalse(any(k[0] == self.sid for k in ilo._CLIENTS))
        self.assertFalse(any(s["id"] == self.sid for s in ilo.load_servers()))


if __name__ == "__main__":
    unittest.main()
