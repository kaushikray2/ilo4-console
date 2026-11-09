#!/usr/bin/env python3
import base64, hashlib, hmac, http.client, json, os, secrets, ssl, threading, time
import urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urljoin
DATA_DIR = os.environ.get("ILO_DATA_DIR", "/app/data")
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
PORT = int(os.environ.get("PORT", "8080"))
SERVERS_FILE = os.path.join(DATA_DIR, "servers.json")
_LOCK = threading.Lock()
_SSL = ssl._create_unverified_context()

AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
KEY_FILE = os.path.join(DATA_DIR, ".key")
AUDIT_FILE = os.path.join(DATA_DIR, "audit.log")
_SESSIONS = {}
_LOGIN_FAILS = {}
_AUTH_LOCK = threading.Lock()
def _b64(b): return base64.b64encode(b).decode()
def _ub64(s): return base64.b64decode(s.encode())
def console_password_set(): return os.path.isfile(AUTH_FILE)
def set_console_password(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200000)
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(AUTH_FILE, "w") as f: json.dump({"algo": "pbkdf2-sha256", "iter": 200000, "salt": _b64(salt), "hash": _b64(dk)}, f)
    os.chmod(AUTH_FILE, 0o600)
def check_console_password(pw):
    try:
        with open(AUTH_FILE) as f: rec = json.load(f)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), _ub64(rec["salt"]), int(rec["iter"]))
        return hmac.compare_digest(_b64(dk), rec["hash"])
    except Exception: return False
def new_session():
    tok = secrets.token_urlsafe(32)
    with _AUTH_LOCK: _SESSIONS[tok] = time.time() + 12 * 3600
    return tok
def session_ok(tok):
    if not tok: return False
    with _AUTH_LOCK:
        exp = _SESSIONS.get(tok)
        if exp and exp > time.time(): return True
        _SESSIONS.pop(tok, None)
    return False
def drop_session(tok):
    with _AUTH_LOCK: _SESSIONS.pop(tok, None)
def _key():
    try:
        with open(KEY_FILE, "rb") as f: return f.read().strip()
    except Exception:
        k = secrets.token_bytes(32)
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(KEY_FILE, "wb") as f: f.write(k)
        os.chmod(KEY_FILE, 0o600)
        return k
def _stream(key, nonce, n):
    out = b""; ctr = 0
    while len(out) < n:
        out += hmac.new(key, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest(); ctr += 1
    return out
def enc_secret(plain):
    if not plain or plain.startswith("enc1:"): return plain
    key = _key(); nonce = secrets.token_bytes(16); data = plain.encode()
    ct = bytes(a ^ b for a, b in zip(data, _stream(key, nonce, len(data))))
    tag = hmac.new(key, b"tag" + nonce + ct, hashlib.sha256).digest()[:16]
    return "enc1:" + _b64(nonce + ct + tag)
def dec_secret(stored):
    if not stored or not stored.startswith("enc1:"): return stored
    try:
        raw = _ub64(stored[5:]); nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
        key = _key()
        want = hmac.new(key, b"tag" + nonce + ct, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, want): return ""
        return bytes(a ^ b for a, b in zip(ct, _stream(key, nonce, len(ct)))).decode()
    except Exception: return ""
def audit(event, ip="", **kw):
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, "ip": ip}
    rec.update(kw)
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(AUDIT_FILE, "a") as f: f.write(json.dumps(rec) + "\n")
    except Exception: pass

def load_servers():
    try:
        with open(SERVERS_FILE) as f: data = json.load(f)
        if not isinstance(data, list): return []
    except Exception:
        return []
    for s in data:
        if s.get("password"): s["password"] = dec_secret(s["password"])
    return data

def save_servers(servers):
    os.makedirs(DATA_DIR, exist_ok=True)
    stored = []
    for s in servers:
        c = dict(s)
        if c.get("password"): c["password"] = enc_secret(c["password"])
        stored.append(c)
    tmp = SERVERS_FILE + ".tmp"
    with open(tmp, "w") as f: json.dump(stored, f, indent=2)
    os.replace(tmp, SERVERS_FILE)
    try: os.chmod(SERVERS_FILE, 0o600)
    except Exception: pass

def public(s):
    out = {k: v for k, v in s.items() if k != "password"}
    out["has_password"] = bool(s.get("password"))
    return out

def find_server(sid):
    for s in load_servers():
        if s["id"] == sid: return s
    return None


class _AuthNeeded(Exception): pass
class _NoSession(Exception): pass

class _IloClient:
    """One persistent HTTPS connection + Redfish session token per iLO.
    Measured against a Gen8 iLO 4: ~0.26-0.85 s/call vs ~2.34 s for a fresh TLS +
    Basic-auth connection per call. All use is serialized per server
    (the iLO serializes requests internally anyway)."""
    def __init__(self, server):
        self.host = server['host']; self.user = server.get('username', ''); self.pw = server.get('password', '')
        self.lock = threading.RLock(); self.conn = None; self.token = None; self.session_ok = None; self.redir = {}; self.sess_path = None; self.fail_at = 0
    def close_session(self):
        with self.lock:
            if self.conn is not None and self.token and self.sess_path:
                try:
                    self.conn.request('DELETE', self.sess_path, headers={'X-Auth-Token': self.token})
                    r = self.conn.getresponse(); r.read()
                except Exception: pass
            self._drop(); self.sess_path = None
    def _drop(self):
        try:
            if self.conn: self.conn.close()
        except Exception: pass
        self.conn = None; self.token = None
    def _login(self):
        c = http.client.HTTPSConnection(self.host, 443, context=_SSL, timeout=30)
        payload = json.dumps({'UserName': self.user, 'Password': self.pw})
        path = '/redfish/v1/SessionService/Sessions/'
        try:
            for _ in range(3):
                c.request('POST', path, payload, {'Content-Type': 'application/json'})
                r = c.getresponse(); r.read()
                if r.status in (301, 302, 303, 307, 308) and r.getheader('Location'):
                    path = urlparse(urljoin(f'https://{self.host}{path}', r.getheader('Location'))).path
                    continue
                break
        except Exception:
            c.close(); raise
        tok = r.getheader('X-Auth-Token')
        if r.status not in (200, 201) or not tok:
            c.close(); self.session_ok = False; self.fail_at = time.time()
            raise _NoSession(f'session login HTTP {r.status}')
        self.session_ok = True; self.token = tok; self.conn = c
        loc = r.getheader('Location')
        self.sess_path = urlparse(loc).path if loc else None
    def request(self, method, path, body=None, timeout=6):
        if self.session_ok is False and time.time() - self.fail_at < 60: raise _NoSession('session login cooling down')
        if self.session_ok is False: self.session_ok = None
        with self.lock:
            t0 = time.time(); last = None
            for attempt in range(3):
                try:
                    if self.conn is None or self.token is None: self._login()
                    return self._once(method, path, body, t0)
                except _NoSession: raise
                except _AuthNeeded:
                    self._drop()
                    if attempt == 2: raise RuntimeError('iLO session rejected after re-login')
                except Exception as e:
                    last = e; self._drop()
                    if attempt == 2: raise
            raise last
    def _once(self, method, path, body, t0):
        from urllib.parse import urljoin
        data = json.dumps(body) if body is not None else None
        cur_path, cur_method, cur_data = self.redir.get(path, path), method, data
        for hop in range(6):
            headers = {'X-Auth-Token': self.token, 'Accept': 'application/json'}
            if cur_data is not None: headers['Content-Type'] = 'application/json'
            self.conn.request(cur_method, cur_path, cur_data, headers)
            r = self.conn.getresponse(); raw = r.read()
            if r.status in (301, 302, 303, 307, 308) and r.getheader('Location'):
                u = urlparse(urljoin(f'https://{self.host}{cur_path}', r.getheader('Location')))
                cur_path = u.path + (('?' + u.query) if u.query else '')
                if r.status == 303: cur_method = 'GET'; cur_data = None
                continue
            if r.status == 401: raise _AuthNeeded()
            if r.status >= 400:
                raise urllib.error.HTTPError(f'https://{self.host}{cur_path}', r.status, r.reason, r.headers, None)
            if cur_path != path: self.redir[path] = cur_path
            text = raw.decode('utf-8', 'replace')
            return (json.loads(text) if text.strip() else {}), int((time.time() - t0) * 1000)
        raise RuntimeError('too many redirects from iLO')

_CLIENTS = {}
_CLIENTS_LOCK = threading.Lock()

def _close_all_sessions():
    with _CLIENTS_LOCK: clients = list(_CLIENTS.values())
    for c in clients:
        try: c.close_session()
        except Exception: pass

import atexit; atexit.register(_close_all_sessions)
def _client_for(server):
    key = (server['id'], server.get('username', ''), server.get('password', ''))
    with _CLIENTS_LOCK:
        c = _CLIENTS.get(key)
        if c is None:
            c = _IloClient(server); _CLIENTS[key] = c
        return c

def _redfish_legacy(server, method, path, body=None, timeout=6):
    from urllib.parse import urljoin
    url = f"https://{server['host']}{path}"
    data = json.dumps(body).encode() if body is not None else None
    t0 = time.time()
    for hop in range(6):
        req = urllib.request.Request(url, data=data, method=method)
        creds = f"{server.get('username','')}:{server.get('password','')}"
        req.add_header("Authorization", "Basic " + base64.b64encode(creds.encode()).decode())
        req.add_header("Accept", "application/json")
        if data: req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=_SSL, timeout=timeout) as r:
                raw = r.read().decode("utf-8", "replace")
                return (json.loads(raw) if raw.strip() else {}), int((time.time()-t0)*1000)
        except urllib.error.HTTPError as e:
            loc = None
            try: loc = e.headers.get("Location")
            except Exception: pass
            if e.code in (301, 302, 303, 307, 308) and loc:
                if e.code == 303:
                    method = "GET"; data = None
                url = urljoin(url, loc)
                continue
            raise
    raise RuntimeError("too many redirects from iLO")

def redfish(server, method, path, body=None, timeout=6):
    try:
        return _client_for(server).request(method, path, body, timeout)
    except _NoSession:
        return _redfish_legacy(server, method, path, body, timeout)

def probe(server, detail=False):
    out = {"id": server["id"], "name": server.get("name") or server["host"],
           "host": server["host"], "power": "unknown", "health": "unknown",
           "reachable": False, "latency_ms": None, "power_watts": None}
    try:
        sysd, ms = redfish(server, "GET", "/redfish/v1/Systems/1")
        out["reachable"] = True; out["latency_ms"] = ms
        out["power"] = (sysd.get("PowerState") or "unknown").lower()
        out["health"] = ((sysd.get("Status") or {}).get("Health") or "unknown").lower()
        out["model"] = sysd.get("Model"); out["serial"] = sysd.get("SerialNumber")
        out["bios"] = sysd.get("BiosVersion")
        proc = sysd.get("ProcessorSummary") or {}; mem = sysd.get("MemorySummary") or {}
        out["cpu"] = f"{proc.get('Count','?')}x {proc.get('Model','')}".strip()
        if mem.get("TotalSystemMemoryGiB"): out["memory_gib"] = mem["TotalSystemMemoryGiB"]
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"; return out
    pw_doc = None
    try:
        pw_doc, _ = redfish(server, "GET", "/redfish/v1/Chassis/1/Power", timeout=4)
        pcs = pw_doc.get("PowerControl") or []
        if pcs and pcs[0].get("PowerConsumedWatts") is not None:
            out["power_watts"] = pcs[0]["PowerConsumedWatts"]
    except Exception: pass
    if detail: out["detail"] = {"system": sysd, "power": pw_doc or {}}
    return out

_CACHE = {}
_CACHE_LOCK = threading.Lock()
def cached(key, ttl, fn):
    now = time.time()
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if hit and now - hit[0] < ttl: return hit[1]
    val = fn()
    with _CACHE_LOCK: _CACHE[key] = (now, val)
    return val
REFRESH = {"status": 25, "thermal": 45, "logs": 120}
def cache_put(key, val):
    with _CACHE_LOCK: _CACHE[key] = (time.time(), val)
def cache_get(key):
    with _CACHE_LOCK: hit = _CACHE.get(key)
    if not hit: return None, None
    return hit[1], time.time() - hit[0]
def cache_drop(sid):
    with _CACHE_LOCK:
        for k in [k for k in _CACHE if isinstance(k, tuple) and k[0] == sid]: del _CACHE[k]
def _refresh_server(server):
    sid = server["id"]
    jobs = [("status", lambda: probe(server, detail=True)), ("thermal", lambda: fetch_thermal(server)), ("logs", lambda: fetch_logs(server))]
    for kind, fn in jobs:
        _, age = cache_get((sid, kind))
        if age is not None and age < REFRESH[kind]: continue
        try: cache_put((sid, kind), fn())
        except Exception: pass
def _refresher():
    while True:
        try:
            with ThreadPoolExecutor(max_workers=4) as ex: list(ex.map(_refresh_server, load_servers()))
        except Exception: pass
        time.sleep(3)

def fetch_thermal(server):
    body, _ = redfish(server, "GET", "/redfish/v1/Chassis/1/Thermal", timeout=8)
    return body
def fetch_logs(server):
    def shape(m):
        return {"created": m.get("Created"), "severity": m.get("Severity"), "message": m.get("Message")}
    for path in ["/redfish/v1/Managers/1/LogServices/IEL/Entries", "/redfish/v1/Managers/1/LogServices/IML/Entries"]:
        try:
            body, _ = redfish(server, "GET", path, timeout=8)
        except Exception:
            continue
        items = [m for m in (body.get("Items") or []) if m.get("Message")]
        if items:
            total = body.get("Total") or body.get("Members@odata.count") or len(items)
            if total > len(items):
                import math
                last = math.ceil(total / 30)
                extra = []
                for p in sorted({last - 1, last} - {1}):
                    if p < 2: continue
                    try:
                        pb, _ = redfish(server, "GET", f"{path}?page={p}", timeout=8)
                        extra += [m for m in (pb.get("Items") or []) if m.get("Message")]
                    except Exception: pass
                if extra: items = extra
            items.sort(key=lambda m: (m.get("RecordId") or 0, m.get("Created") or ""))
            return [shape(m) for m in reversed(items[-50:])]
        members = [m for m in (body.get("Members") or []) if m.get("Message")]
        if members:
            return [shape(m) for m in reversed(members[:50])]
        links = [m.get("@odata.id") for m in (body.get("Members") or []) if m.get("@odata.id")]
        if links:
            def one(url):
                try:
                    e, _ = redfish(server, "GET", url, timeout=8)
                    return shape(e) if e.get("Message") else None
                except Exception:
                    return None
            with ThreadPoolExecutor(max_workers=6) as ex:
                got = [r for r in ex.map(one, links[:30]) if r]
            if got:
                return list(reversed(got))
    return []

def server_detail(server):
    paths = [("system","/redfish/v1/Systems/1"),("chassis","/redfish/v1/Chassis/1"),("manager","/redfish/v1/Managers/1"),("thermal","/redfish/v1/Chassis/1/Thermal"),("power","/redfish/v1/Chassis/1/Power")]
    def fetch(kp):
        key, path = kp
        try:
            body, _ = redfish(server, "GET", path, timeout=8); return key, body
        except Exception as e:
            return key, {"_error": f"{type(e).__name__}: {e}"}
    with ThreadPoolExecutor(max_workers=5) as ex:
        d = dict(ex.map(fetch, paths))
    d["logs"] = []
    for path in ["/redfish/v1/Managers/1/LogServices/IEL/Entries", "/redfish/v1/Managers/1/LogServices/IML/Entries"]:
        try:
            body, _ = redfish(server, "GET", path, timeout=5)
            members = body.get("Members") or []
            if members:
                d["logs"] = [{"created": m.get("Created"), "severity": m.get("Severity"), "message": m.get("Message")} for m in members[:50]]; break
        except Exception: continue
    return d

POWER_ACTIONS = {"On","GracefulShutdown","ForceOff","ForceRestart","PushPowerButton","Nmi","GracefulRestart"}

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *args):
        print("%s %s" % (self.address_string(), fmt % args), flush=True)
    def send_json(self, code, obj, headers=None):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(raw)
    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")
    def _cookie_token(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            part = part.strip()
            if part.startswith("ilo_session="): return part.split("=", 1)[1]
        return None
    def _authed(self): return session_ok(self._cookie_token())
    def _session_headers(self, tok):
        if tok: return {"Set-Cookie": f"ilo_session={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200"}
        return {"Set-Cookie": "ilo_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"}
    def _auth_api(self, method, action, ip):
        if action == "me" and method == "GET":
            return self.send_json(200, {"setup_needed": not console_password_set(), "authed": self._authed()})
        if action == "setup" and method == "POST":
            if console_password_set(): return self.send_json(403, {"error": "console password already set"})
            pw = (self.read_json().get("password") or "")
            if len(pw) < 6: return self.send_json(400, {"error": "password must be at least 6 characters"})
            set_console_password(pw); audit("console_setup", ip)
            return self.send_json(200, {"ok": True}, self._session_headers(new_session()))
        if action == "login" and method == "POST":
            now = time.time(); count, locked = _LOGIN_FAILS.get(ip, (0, 0))
            if locked > now: return self.send_json(429, {"error": "too many failed logins - wait a minute"})
            pw = (self.read_json().get("password") or "")
            if console_password_set() and check_console_password(pw):
                _LOGIN_FAILS.pop(ip, None); audit("login_ok", ip)
                return self.send_json(200, {"ok": True}, self._session_headers(new_session()))
            count += 1; _LOGIN_FAILS[ip] = (count, now + 60 if count >= 5 else 0)
            audit("login_fail", ip, attempts=count)
            return self.send_json(401, {"error": "wrong password"})
        if action == "logout" and method == "POST":
            drop_session(self._cookie_token()); audit("logout", ip)
            return self.send_json(200, {"ok": True}, self._session_headers(None))
        return self.send_json(404, {"error": "not found"})
    def api(self, method, path, qs):
        parts = [p for p in path.split("/") if p]
        ip = self.client_address[0] if self.client_address else ""
        if parts[:2] == ["api", "auth"]:
            return self._auth_api(method, parts[2] if len(parts) > 2 else "", ip)
        if parts != ["api", "health"] and not self._authed():
            return self.send_json(401, {"error": "login required"})
        if parts == ["api", "servers"]:
            if method == "GET":
                return self.send_json(200, [public(s) for s in load_servers()])
            if method == "POST":
                b = self.read_json()
                if not b.get("host") or not b.get("username"):
                    return self.send_json(400, {"error": "host and username are required"})
                with _LOCK:
                    servers = load_servers()
                    s = {"id": str(int(time.time()*1000))[-8:] + os.urandom(2).hex(),
                         "name": b.get("name",""), "host": b["host"].strip(),
                         "username": b["username"], "password": b.get("password",""),
                         "group": b.get("group",""), "location": b.get("location",""),
                         "model_note": b.get("model_note","")}
                    servers.append(s); save_servers(servers)
                audit("server_add", ip, server=s.get("name") or s["host"], host=s["host"])
                return self.send_json(201, public(s))
        if len(parts) >= 3 and parts[:2] == ["api", "servers"]:
            sid = parts[2]; server = find_server(sid)
            if not server: return self.send_json(404, {"error": "no such server"})
            if len(parts) == 3 and method == "PUT":
                b = self.read_json()
                with _LOCK:
                    servers = load_servers()
                    for s in servers:
                        if s["id"] == sid:
                            for k in ("name","host","username","group","location","model_note"):
                                if k in b: s[k] = b[k]
                            if b.get("password"): s["password"] = b["password"]
                            save_servers(servers); return self.send_json(200, public(s))
            if len(parts) == 3 and method == "DELETE":
                with _LOCK: save_servers([s for s in load_servers() if s["id"] != sid])
                cache_drop(sid)
                audit("server_remove", ip, server=server.get("name") or server["host"], host=server["host"])
                return self.send_json(200, {"ok": True})
            if len(parts) == 4 and parts[3] == "status" and method == "GET":
                detail = qs.get("detail") == ["1"]
                val, age = cache_get((sid, "status"))
                if val is None:
                    val = probe(server, detail=True); cache_put((sid, "status"), val); age = 0
                out = dict(val)
                if not detail: out.pop("detail", None)
                out["age_s"] = int(age)
                return self.send_json(200, out)
            if len(parts) == 4 and parts[3] == "thermal" and method == "GET":
                val, _a = cache_get((sid, "thermal"))
                if val is not None: return self.send_json(200, val)
                try:
                    val = fetch_thermal(server); cache_put((sid, "thermal"), val); return self.send_json(200, val)
                except Exception as e: return self.send_json(502, {"error": f"Thermal fetch failed: {e}"})
            if len(parts) == 4 and parts[3] == "logs" and method == "GET":
                val, _a = cache_get((sid, "logs"))
                if val is not None: return self.send_json(200, {"logs": val})
                try:
                    val = fetch_logs(server); cache_put((sid, "logs"), val); return self.send_json(200, {"logs": val})
                except Exception as e: return self.send_json(502, {"error": f"Log fetch failed: {e}"})
            if len(parts) == 4 and parts[3] == "credentials" and method == "GET":
                return self.send_json(200, {"username": server.get("username",""), "password": server.get("password","")})
            if len(parts) == 4 and parts[3] == "power" and method == "POST":
                b = self.read_json(); action = b.get("action")
                if action not in POWER_ACTIONS:
                    return self.send_json(400, {"error": "invalid action"})
                _val, _age = cache_get((sid, "status"))
                _allowed = None
                if _val and _val.get("detail"):
                    _acts = (_val["detail"].get("system") or {}).get("Actions") or {}
                    _allowed = (_acts.get("#ComputerSystem.Reset") or {}).get("ResetType@Redfish.AllowableValues")
                if _allowed and action not in _allowed:
                    return self.send_json(400, {"error": f"this iLO does not support {action} - supported power actions: {', '.join(_allowed)}. On iLO 4, PushPowerButton is the graceful ACPI shutdown."})
                try:
                    redfish(server, "POST", "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset", {"ResetType": action}, timeout=10)
                    cache_drop(sid)
                    audit("power", ip, server=server.get("name") or server["host"], host=server["host"], action=action, result="ok")
                    return self.send_json(200, {"ok": True, "action": action})
                except Exception as e:
                    audit("power", ip, server=server.get("name") or server["host"], host=server["host"], action=action, result="error")
                    return self.send_json(502, {"error": f"Redfish power call failed: {e}"})
        if parts == ["api", "fleet"] and method == "GET":
            servers = load_servers()
            with ThreadPoolExecutor(max_workers=8) as ex:
                results = list(ex.map(lambda s: (lambda v, a: (dict(v, age_s=int(a), detail=None) if v is not None else probe(s)))(*cache_get((s["id"], "status"))), servers))
            running = [r for r in results if r["power"] == "on"]
            return self.send_json(200, {
                "total": len(results), "running": len(running),
                "off": sum(1 for r in results if r["power"] == "off"),
                "degraded": sum(1 for r in results if r["reachable"] and r["health"] not in ("ok","unknown")),
                "unreachable": sum(1 for r in results if not r["reachable"]),
                "total_watts": sum(r["power_watts"] for r in results if r["power_watts"]) or None,
                "running_now": [{"id": r["id"], "name": r["name"], "host": r["host"], "power_watts": r["power_watts"]} for r in running],
                "servers": results})
        if parts == ["api", "health"] and method == "GET":
            return self.send_json(200, {"ok": True})
        return self.send_json(404, {"error": "not found"})
    def handle_method(self, method):
        u = urlparse(self.path)
        if u.path.startswith("/api/"):
            return self.api(method, u.path, parse_qs(u.query))
        rel = "index.html" if u.path in ("/", "") else u.path.lstrip("/")
        fp = os.path.normpath(os.path.join(STATIC_DIR, rel))
        if not fp.startswith(STATIC_DIR) or not os.path.isfile(fp):
            return self.send_json(404, {"error": "not found"})
        ctype = {".html":"text/html",".js":"text/javascript",".css":"text/css",".svg":"image/svg+xml"}.get(os.path.splitext(fp)[1], "text/plain")
        with open(fp, "rb") as f: raw = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)
    def do_GET(self): self.handle_method("GET")
    def do_POST(self): self.handle_method("POST")
    def do_PUT(self): self.handle_method("PUT")
    def do_DELETE(self): self.handle_method("DELETE")

if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"iLO console on :{PORT} (data: {DATA_DIR})", flush=True)
    try:
        with open(SERVERS_FILE) as f: _raw = json.load(f)
        if any(s.get("password") and not str(s["password"]).startswith("enc1:") for s in _raw):
            save_servers(load_servers()); print("migrated saved iLO passwords to encrypted storage", flush=True)
    except Exception: pass
    threading.Thread(target=_refresher, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
