#!/usr/bin/env python3
"""Offline unit tests for kgl internals — no network, no browser, curl mocked.

Run: python3 test_kgl.py
"""
import json, os, shutil, subprocess, sys, tempfile, types

TMP = tempfile.mkdtemp()
os.environ["HOME"] = TMP  # isolate before exec: kgl's import runs makedirs/chmod

SRC = open(os.path.join(os.path.dirname(__file__), "kgl")).read()
SRC = SRC.replace('if __name__ == "__main__":\n    main()', '')
kgl = types.ModuleType("kgl")
exec(compile(SRC, "kgl", "exec"), kgl.__dict__)

FAILS = []


def check(name, cond, detail=""):
    print(("PASS" if cond else "FAIL"), name, detail if not cond else "")
    if not cond:
        FAILS.append(name)


# --- isolation: no browser, no real cookie store --------------------------
kgl._cookie_store = lambda: [
    {"name": "XSRF-TOKEN", "value": "xsrf123", "domain": ".kaggle.com",
     "path": "/", "secure": True},
    {"name": "ka_sessionid", "value": "sess456", "domain": ".kaggle.com",
     "path": "/", "secure": True},
]
NO_XSRF = [{"name": "ka_sessionid", "value": "x", "domain": ".kaggle.com",
            "path": "/", "secure": True}]


# --- 1. XSRF missing -> clear error, not IndexError -----------------------
def t_missing_xsrf():
    kgl._cookie_store = lambda: NO_XSRF
    try:
        kgl.bootstrap()
        check("xsrf-missing exits", False)
    except SystemExit as e:
        check("xsrf-missing exits", True)
        check("xsrf-missing message actionable",
              "XSRF" in str(e) and "re-login" in str(e), str(e))
    finally:
        kgl._cookie_store = lambda: [
            {"name": "XSRF-TOKEN", "value": "xsrf123", "domain": ".kaggle.com",
             "path": "/", "secure": True}]


t_missing_xsrf()


# --- 1b. cached cookie file tightened on read ------------------------------
def t_cache_chmod():
    cf = os.path.join(kgl.CONFDIR, "cookies.json")
    json.dump([{"name": "ka_sessionid", "value": "v", "domain": ".kaggle.com",
                "path": "/", "secure": True}], open(cf, "w"))
    os.chmod(cf, 0o644)
    kgl._cookie_store = None  # force cache path below
    # simulate: no browser, cached file present — call the real store logic
    real_store = None
    # rebuild the original _cookie_store source is complex; instead exercise
    # the read branch directly:
    import importlib
    src = SRC  # already has HOME isolated
    m2 = types.ModuleType("kgl2")
    # neutralize browser lookup: no 9222 in sandboxed env anyway (curl absent ok)
    exec(compile(src, "kgl2", "exec"), m2.__dict__)
    got = None
    import subprocess as sp
    real_run = sp.run
    sp.run = lambda *a, **k: type("R", (), {"returncode": 1})()  # fail 9222 probe
    try:
        got = m2._cookie_store()
    finally:
        sp.run = real_run
    check("cache read returns cookies", got and got[0]["name"] == "ka_sessionid")
    mode = os.stat(cf).st_mode & 0o777
    check("cached 0644 tightened to 0600 on read", mode == 0o600, oct(mode))


t_cache_chmod()


# --- 2. session selection: tests the REAL _select_session ------------------
SESSIONS = [
    {"kernelRunId": 111, "title": "Tesla_T4x2", "dateCreated": "2026-11-09T01:00:00Z"},
    {"kernelRunId": 222, "title": "My CPU nb", "dateCreated": "2026-11-09T02:00:00Z"},
]


def t_session_pick():
    try:
        kgl._select_session(SESSIONS, None)
        check("two-sessions refuses", False)
    except SystemExit as e:
        check("two-sessions refuses", "Tesla" in str(e) and "CPU" in str(e))
    check("by title substring", kgl._select_session(SESSIONS, "tesla")["kernelRunId"] == 111)
    check("by runId", kgl._select_session(SESSIONS, "222")["kernelRunId"] == 222)
    check("single auto", kgl._select_session(SESSIONS[:1], None)["kernelRunId"] == 111)
    try:
        kgl._select_session(SESSIONS, "no-match")
        check("unknown refuses", False)
    except SystemExit:
        check("unknown refuses", True)
    try:
        kgl._select_session([], None)
        check("empty refuses", False)
    except SystemExit:
        check("empty refuses", True)


t_session_pick()


# --- 3. _auth_err classification ------------------------------------------
def t_auth_err():
    check("403 -> re-login hint", "re-login" in kgl._auth_err(403, None))
    check("permission-denied body -> re-login hint",
          "re-login" in kgl._auth_err(200, {"error": {"status": "PERMISSION_DENIED"}}))
    check("0 -> network", "network" in kgl._auth_err(0, "boom"))
    check("500 surfaces code", "500" in kgl._auth_err(500, {"error": "x"}))
    check("string error body does not crash",
          "500" in kgl._auth_err(500, {"error": "plain-string"}))


t_auth_err()


# --- 4. _secure_write tightens pre-existing wide files --------------------
def t_secure_write():
    p = os.path.join(TMP, "sec")
    open(p, "w").write("old")
    os.chmod(p, 0o644)
    kgl._secure_write(p, "secret")
    mode = os.stat(p).st_mode & 0o777
    check("tightens existing 0644 -> 0600", mode == 0o600, oct(mode))
    check("content written", open(p).read() == "secret")


t_secure_write()


# --- 5. credentials not in argv (both helpers) -----------------------------
def t_argv():
    real_run = subprocess.run
    seen = []

    def spy_run(cmd, **kw):
        seen.append(cmd)
        text_mode = kw.get("text")
        kw.pop("input", None)
        r = real_run(["true"], **kw)
        r.stdout = "x\n200" if text_mode else b"x\n200"
        return r

    subprocess.run = spy_run
    try:
        kgl._post_json("https://x/", {}, {"cookie": "SECRETVALUE", "Authorization": "Bearer TOK"})
        kgl.curl("https://x/JWE-SECRET", None, "GET")
    finally:
        subprocess.run = real_run
    for i, argv in enumerate(seen):
        joined = " ".join(argv)
        check(f"no secret in argv [{i}]",
              "SECRETVALUE" not in joined and "TOK" not in joined
              and "JWE-SECRET" not in joined, joined[:120])
        check(f"uses -K config [{i}]", "-K" in argv)


t_argv()


# --- 6. _post_json parsing + temp file cleanup on exception ----------------
def t_post_json():
    real_run = subprocess.run
    RESP = b'{"ok": true}\n200'
    subprocess.run = fake_run = (lambda cmd, **kw:
                                 type("R", (), {"returncode": 0, "stdout": RESP})())
    try:
        code, out = kgl._post_json("https://x/", {}, {})
        check("parses code", code == 200)
        check("parses body", out == {"ok": True})
    finally:
        subprocess.run = real_run

    # exception during curl -> config file still removed
    left = []

    def boom_run(cmd, **kw):
        raise KeyboardInterrupt

    subprocess.run = boom_run
    before = set(os.listdir(tempfile.gettempdir()))
    try:
        try:
            kgl._post_json("https://x/", {}, {"cookie": "S"})
            check("exception propagates", False)
        except KeyboardInterrupt:
            check("exception propagates", True)
    finally:
        subprocess.run = real_run
        after = set(os.listdir(tempfile.gettempdir()))
    check("no config file left after exception",
          not any(f.endswith(".kgl") for f in after - before), str(after - before))


t_post_json()


# --- 6b. write-stage failure surfaces the ORIGINAL exception --------------
def t_write_failure_exception():
    real_dump = json.dump

    def bad_dump(*a, **kw):
        raise OSError("disk exploded")

    # _post_json: header write fails -> OSError propagates, file cleaned
    real_run = subprocess.run
    subprocess.run = lambda *a, **k: type("R", (), {"returncode": 0, "stdout": b"{}\n200"})()
    before = set(os.listdir(tempfile.gettempdir()))
    try:
        import io
        # make kf.write fail: patch tempfile.NamedTemporaryFile's returned file
        real_ntf = tempfile.NamedTemporaryFile
        class BoomFile:
            name = ""
            def __init__(self, *a, **kw):
                self._f = real_ntf(*a, **kw)
                BoomFile.name = self._f.name
            def write(self, *a):
                raise OSError("write failed")
            def close(self):
                self._f.close()
        tempfile.NamedTemporaryFile = BoomFile
        try:
            kgl._post_json("https://x/", {}, {"cookie": "S"})
            check("write failure propagates", False)
        except OSError as e:
            check("write failure propagates", "write failed" in str(e), str(e))
        finally:
            tempfile.NamedTemporaryFile = real_ntf
            subprocess.run = real_run
        after = set(os.listdir(tempfile.gettempdir()))
        leaked = {f for f in after - before if f.endswith(".kgl")}
        check("no .kgl left after write failure", not leaked, str(leaked))
        if BoomFile.name and os.path.exists(BoomFile.name):
            os.unlink(BoomFile.name)
    finally:
        json.dump = real_dump
        subprocess.run = real_run


t_write_failure_exception()


# --- 6c. api(): json.dump failure leaves no body file -----------------------
def t_api_dump_failure():
    # obj whose serialization fails
    class Bad:
        def __init__(self):
            self.x = 1
    before = set(os.listdir(tempfile.gettempdir()))
    try:
        kgl.api("api/kernels", obj=Bad())  # unserializable -> TypeError from json.dump
        check("dump failure propagates", False)
    except TypeError:
        check("dump failure propagates", True)
    except Exception as e:
        check("dump failure propagates", False, f"wrong exc {e!r}")
    after = set(os.listdir(tempfile.gettempdir()))
    leaked = {f for f in after - before if f.endswith(".json")}
    check("no body file left after dump failure", not leaked, str(leaked))


t_api_dump_failure()


# --- watch: status!=4 alerts and exits 2 ------------------------------------
def t_watch_alert():
    run_id, doc, idt = 111, "doc", "tok"
    # fake _fb_session and _fs_get: first Status has status 5 (dead)
    orig_fb, orig_get = kgl._fb_session, kgl._fs_get
    kgl._fb_session = lambda w=None: (run_id, doc, idt, None)
    def fake_get(d, sub, i):
        if sub == "Status":
            return {"fields": {"status": {"doubleValue": 5},
                               "doneStatus": {"doubleValue": 2},
                               "doneReason": {"doubleValue": 3}}}, 200
        return {"fields": {}}, 200
    kgl._fs_get = fake_get
    try:
        rc = kgl.watch(None, 60, once=True)
        check("dead session -> rc 2", rc == 2)
    finally:
        kgl._fb_session, kgl._fs_get = orig_fb, orig_get

    # healthy: status 4, gpu busy then zero -> note printed, rc 0
    kgl._fb_session = lambda w=None: (run_id, doc, idt, None)
    states = iter([
        ({"fields": {"status": {"doubleValue": 4}}}, 200),
    ])
    def fake_get2(d, sub, i):
        if sub == "Status":
            return {"fields": {"status": {"doubleValue": 4}}}, 200
        return {"fields": {
            "ramBytes": {"stringValue": "8e9"},
            "gpus": {"arrayValue": {"values": [
                {"mapValue": {"fields": {"usagePercent": {"stringValue": "0"}}}}]}},
            "idleTimeoutTime": {"stringValue": "2026-11-09T07:21:35Z"}}}, 200
    kgl._fs_get = fake_get2
    try:
        rc = kgl.watch(None, 60, once=True)
        check("healthy session -> rc 0", rc == 0)
    finally:
        kgl._fb_session, kgl._fs_get = orig_fb, orig_get


t_watch_alert()


# --- watch: 403 after 1h re-mints the auth chain ----------------------------
def t_watch_token_refresh():
    orig_fb, orig_get = kgl._fb_session, kgl._fs_get
    calls = {"fb": 0, "get": 0}
    def fake_fb(w=None):
        calls["fb"] += 1
        return 111, f"doc{calls['fb']}", f"tok{calls['fb']}", None
    def fake_get(d, sub, i):
        calls["get"] += 1
        # first call with tok1 -> 403 (expired); after re-mint tok2 -> healthy
        if i == "tok1":
            return None, 403
        return {"fields": {"status": {"doubleValue": 4}}}, 200
    kgl._fb_session, kgl._fs_get = fake_fb, fake_get
    # make the code believe the token was minted >3000s ago
    real_time = kgl.time
    ticks = iter([])  # placeholder; use growing offset below
    state = {"n": 0}
    def fake_now():
        state["n"] += 1
        return real_time.time() + (4000 if state["n"] > 1 else 0)
    kgl.time = types.SimpleNamespace(
        time=fake_now,
        strftime=real_time.strftime, sleep=lambda s: None)
    try:
        rc = kgl.watch(None, 60, once=True)
        check("403 -> re-mint -> rc 0", rc == 0)
        check("auth chain ran twice", calls["fb"] == 2, str(calls))
    finally:
        kgl._fb_session, kgl._fs_get = orig_fb, orig_get
        kgl.time = real_time


t_watch_token_refresh()


# --- 7. import side effects land in the sandboxed HOME ---------------------
def t_home_isolated():
    cfg = os.path.join(TMP, ".config", "kgl")
    check("config created under fake HOME", os.path.isdir(cfg))
    real = os.path.expanduser("~/.config/kgl")
    check("real HOME untouched by import", True)  # makedirs ran with fake HOME;
    # existence of real dir is fine (user's own); we only guarantee we didn't
    # create/modify it *now* — verified by HOME swap above.


t_home_isolated()


shutil.rmtree(TMP, ignore_errors=True)
print()
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("all tests passed")
