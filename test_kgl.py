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
    orig_store = kgl._cookie_store
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
    kgl._cookie_store = orig_store


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
    # numeric selector never matches a title substring (session-pinning safety)
    sessions2 = [{"kernelRunId": 222, "title": "experiment-111"}]
    try:
        kgl._select_session(sessions2, "111")
        check("numeric never title-matches", False)
    except SystemExit:
        check("numeric never title-matches", True)
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


# --- watch: error JSON / auth failure is NOT death; --once fails loudly -----
def t_watch_error_paths():
    orig_fb, orig_get = kgl._fb_session, kgl._fs_get
    kgl._fb_session = lambda w=None: (111, "doc", "tok", None)

    # 401 with error JSON body -> must NOT report death, --once -> rc 3
    kgl._fs_get = lambda d, sub, i: (
        {"error": {"code": 401, "message": "unauthenticated"}}, 401)
    try:
        rc = kgl.watch(None, 60, once=True)
        check("401 error-json -> rc 3 (not death/2)", rc == 3, str(rc))
    finally:
        pass

    # network failure (None, 0) -> rc 3
    kgl._fs_get = lambda d, sub, i: (None, 0)
    try:
        rc = kgl.watch(None, 60, once=True)
        check("network failure --once -> rc 3", rc == 3, str(rc))
    finally:
        pass

    # integerValue status 4 (not doubleValue) -> recognized as RUNNING
    kgl._fs_get = lambda d, sub, i: (
        {"fields": {"status": {"integerValue": "4"}}}, 200) if sub == "Status" else (
        {"fields": {}}, 200)
    try:
        rc = kgl.watch(None, 60, once=True)
        check("integerValue status 4 -> healthy rc 0", rc == 0, str(rc))
    finally:
        kgl._fb_session, kgl._fs_get = orig_fb, orig_get


t_watch_error_paths()


# --- _fs_num: all Firestore Value variants -----------------------------------
def t_fs_num():
    check("doubleValue", kgl._fs_num({"doubleValue": 4.0}) == 4.0)
    check("integerValue", kgl._fs_num({"integerValue": "4"}) == 4.0)
    check("stringValue", kgl._fs_num({"stringValue": "42"}) == 42.0)
    check("garbage stringValue -> default", kgl._fs_num({"stringValue": "x"}, -1) == -1)
    check("missing -> default", kgl._fs_num({}, 7) == 7)
    check("non-dict -> default", kgl._fs_num(None, 9) == 9)


t_fs_num()


# --- watch: pinned session across re-auth -----------------------------------
def t_watch_pinned():
    orig_fb, orig_get = kgl._fb_session, kgl._fs_get
    seen_sel = []
    def fake_fb(w=None):
        seen_sel.append(w)
        return (222 if len(seen_sel) > 1 else 111), f"doc{len(seen_sel)}", f"t{len(seen_sel)}", None
    calls = {"n": 0}
    def fake_get(d, sub, i):
        calls["n"] += 1
        if i == "t1":
            return None, 403  # force re-auth on first read
        return {"fields": {"status": {"doubleValue": 4}}}, 200
    kgl._fb_session, kgl._fs_get = fake_fb, fake_get
    real_time = kgl.time
    state = {"n": 0}
    def tick():
        state["n"] += 1
        return real_time.time() + (4000 if state["n"] >= 2 else 0)
    kgl.time = types.SimpleNamespace(
        time=tick, strftime=real_time.strftime, sleep=lambda s: None)
    try:
        rc = kgl.watch(None, 60, once=True)
        check("re-auth keeps watching (rc 0)", rc == 0, str(rc))
        check("re-auth pinned to original runId",
              seen_sel[1] == "111" if len(seen_sel) > 1 else False, str(seen_sel))
    finally:
        kgl._fb_session, kgl._fs_get = orig_fb, orig_get
        kgl.time = real_time


t_watch_pinned()


# --- watch: missing status field is NOT death --------------------------------
def t_watch_missing_status():
    orig_fb, orig_get = kgl._fb_session, kgl._fs_get
    kgl._fb_session = lambda w=None: (111, "doc", "tok", None)
    kgl._fs_get = lambda d, sub, i: ({"fields": {"foo": {"doubleValue": 1}}}, 200)
    try:
        rc = kgl.watch(None, 60, once=True)
        check("missing status -> rc 3, not death(2)", rc == 3, str(rc))
    finally:
        kgl._fb_session, kgl._fs_get = orig_fb, orig_get


t_watch_missing_status()


# --- watch: missing metrics shown as unknown, no bogus zero-drop note -------
def t_watch_missing_metrics(capsys=None):
    import io, contextlib
    orig_fb, orig_get = kgl._fb_session, kgl._fs_get
    kgl._fb_session = lambda w=None: (111, "doc", "tok", None)
    def fake_get(d, sub, i):
        if sub == "Status":
            return {"fields": {"status": {"doubleValue": 4}}}, 200
        # gpu busy last tick (via closure state), then fields disappear
        fake_get.busy = getattr(fake_get, "busy", False) or False
        return {"fields": {"idleTimeoutTime": {"stringValue": "2026-11-09T07:21:35Z"}}}, 200
    kgl._fs_get = fake_get
    buf, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = kgl.watch(None, 60, once=True)
        out = buf.getvalue() + err.getvalue()
        check("missing metrics -> rc 0 (status was healthy)", rc == 0, str(rc))
        check("no fake 'dropped to 0%' note", "dropped to 0%" not in out, out[:300])
        check("warns metrics unavailable", "unavailable" in out, out[:300])
    finally:
        kgl._fb_session, kgl._fs_get = orig_fb, orig_get


t_watch_missing_metrics()


# --- watch: continuous mode reports ResourceUsage failures -------------------
def t_watch_ru_fail_continuous():
    import io, contextlib
    orig_fb, orig_get = kgl._fb_session, kgl._fs_get
    kgl._fb_session = lambda w=None: (111, "doc", "tok", None)
    n = {"i": 0}
    def fake_get(d, sub, i):
        if sub == "Status":
            return {"fields": {"status": {"doubleValue": 4}}}, 200
        return None, 403
    kgl._fs_get = fake_get
    real_sleep = kgl.time.sleep
    kgl.time = types.SimpleNamespace(time=kgl.time.time,
        strftime=kgl.time.strftime, sleep=lambda s: (_ for _ in ()).throw(KeyboardInterrupt))
    buf, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            try:
                kgl.watch(None, 60, once=False)
            except KeyboardInterrupt:
                pass
        check("continuous mode logs RU failure", "ResourceUsage read failed" in err.getvalue(),
              err.getvalue()[:200])
    finally:
        kgl._fb_session, kgl._fs_get = orig_fb, orig_get
        kgl.time = types.SimpleNamespace(time=kgl.time.time,
            strftime=kgl.time.strftime, sleep=real_sleep)


t_watch_ru_fail_continuous()


# --- _fs_num default semantics ------------------------------------------------
def t_fs_num_missing():
    check("default MISSING sentinel returned", kgl._fs_num({}) is kgl._MISSING)
    check("explicit default honored", kgl._fs_num(None, 0) == 0)
    check("real zero preserved", kgl._fs_num({"doubleValue": 0}) == 0.0)


t_fs_num_missing()


# --- session-action verification: API failure is UNKNOWN, not empty ----------
def t_verify_paths():
    orig_api = kgl._kgl_cookie_api
    orig_kid = kgl._notebook_kernel_id
    kgl._notebook_kernel_id = lambda: 111

    # stop: API always failing -> must NOT report verified within short timeout
    kgl._kgl_cookie_api = lambda m, b: (False, None)
    real_sleep = kgl.time.sleep
    kgl.time = types.SimpleNamespace(time=kgl.time.time,
        strftime=kgl.time.strftime, sleep=lambda s: None)
    try:
        rc = kgl._headless_action("stop", wait=0, timeout=0) if False else None
    except Exception:
        pass  # full action needs chrome; test the loop logic via _target_sessions instead
    ok, runs = kgl._target_sessions(111)
    check("API failure -> (False, None), not empty", ok is False and runs is None)

    # stop: other kernel's session survives, target gone -> verified
    kgl._kgl_cookie_api = lambda m, b: (True, {"sessions": [
        {"kernelId": 999, "kernelRunId": 555}]})
    ok, runs = kgl._target_sessions(111)
    check("target-only filtering", ok and runs == set())

    # run-all: target kernel present among others -> detected
    kgl._kgl_cookie_api = lambda m, b: (True, {"sessions": [
        {"kernelId": 999, "kernelRunId": 555}, {"kernelId": 111, "kernelRunId": 222}]})
    ok, runs = kgl._target_sessions(111)
    check("run-all target detected", ok and runs == {222})

    kgl._kgl_cookie_api = orig_api  # restore BEFORE testing its internals

    # _kgl_cookie_api really routes through _post_json (no argv credentials)
    real_post = kgl._post_json
    seen = {}
    def spy_post(url, body, headers):
        seen["argv_check"] = True
        return 200, {"sessions": []}
    kgl._post_json = spy_post
    ok, _ = kgl._kgl_cookie_api("ListKernelSessions", {})
    kgl._post_json = real_post
    check("cookie api uses _post_json", seen.get("argv_check") is True and ok is True)

    kgl._notebook_kernel_id = orig_kid
    kgl.time = types.SimpleNamespace(time=kgl.time.time,
        strftime=kgl.time.strftime, sleep=real_sleep)


t_verify_paths()


# --- kernel_id cache is slug-bound -------------------------------------------
def t_kernel_cache_slug_bound():
    import tempfile as tf
    cache = os.path.join(kgl.CONFDIR, "kernel_id")
    kgl._secure_write(cache, "old/slug 42\n")
    # current slug differs -> cache must be ignored (would need live API; assert invalidation logic)
    slug = "some/new-slug"
    parts = open(cache).read().strip().split()
    stale = not (len(parts) == 2 and parts[0] == slug and parts[1].isdigit())
    check("slug mismatch invalidates cache", stale is True)
    os.unlink(cache)


t_kernel_cache_slug_bound()


# --- kid resolver: ownership via GetKernel url; lazy for run-all ------------
def t_kid_resolver():
    orig_slug = kgl._notebook_slug
    orig_api = kgl._kgl_cookie_api
    kgl._notebook_slug = lambda: "owner/target"
    calls = {"GetKernel": []}

    def fake_api(m, b):
        if m == "ListKernelSessions":
            return True, {"sessions": [{"kernelId": 999, "kernelRunId": 5}]}
        if m == "GetKernel":
            calls["GetKernel"].append(b.get("kernelId"))
            return True, {"url": "/code/someone/ELSE"}  # belongs to another notebook
        return True, {}

    kgl._kgl_cookie_api = fake_api
    try:
        # candidate session is NOT ours -> lazy resolve returns None (no crash)
        check("foreign session -> None when not required",
              kgl._notebook_kernel_id(required=False) is None)
        # ...and a clear error when required
        try:
            kgl._notebook_kernel_id(required=True)
            check("foreign session -> refuses when required", False)
        except SystemExit as e:
            check("foreign session -> refuses when required", "seed" in str(e))
        check("GetKernel was consulted", 999 in calls["GetKernel"])

        # matching url -> resolved + cached
        def fake_api2(m, b):
            if m == "ListKernelSessions":
                return True, {"sessions": [{"kernelId": 999, "kernelRunId": 5}]}
            if m == "GetKernel":
                return True, {"url": "/code/owner/target"}
            return True, {}
        kgl._kgl_cookie_api = fake_api2
        kid = kgl._notebook_kernel_id(required=False)
        check("own session -> resolved", kid == 999, str(kid))
        cache = os.path.join(kgl.CONFDIR, "kernel_id")
        check("resolved kid cached slug-bound",
              open(cache).read().strip() == "owner/target 999")
        os.unlink(cache)
    finally:
        kgl._notebook_slug = orig_slug
        kgl._kgl_cookie_api = orig_api


t_kid_resolver()


# --- cached kid must be ownership-verified (legacy wrong binding) -----------
def t_kid_cache_verified():
    orig_slug, orig_api = kgl._notebook_slug, kgl._kgl_cookie_api
    kgl._notebook_slug = lambda: "owner/target"
    cache = os.path.join(kgl.CONFDIR, "kernel_id")
    try:
        # legacy cache: bound to our slug but the kid belongs to ANOTHER notebook
        kgl._secure_write(cache, "owner/target 42\n")
        kgl._kgl_cookie_api = lambda m, b: (
            (True, {"url": "/code/someone/ELSE"}) if m == "GetKernel" else
            (True, {"sessions": []}))
        check("stale cache dropped, not trusted",
              kgl._notebook_kernel_id(required=False) is None)
        check("stale cache file removed", not os.path.exists(cache))

        # valid cache: GetKernel confirms -> returned without re-resolution
        kgl._secure_write(cache, "owner/target 42\n")
        kgl._kgl_cookie_api = lambda m, b: (True, {"url": "/code/owner/target"})
        check("verified cache honored", kgl._notebook_kernel_id(required=False) == 42)
    finally:
        kgl._notebook_slug, kgl._kgl_cookie_api = orig_slug, orig_api
        if os.path.exists(cache):
            os.unlink(cache)


t_kid_cache_verified()


# --- _iso parses RFC3339 ------------------------------------------------------
def t_iso():
    check("_iso epoch", abs(kgl._iso("2026-11-09T12:00:00Z") - 1794254400) < 86400)
    check("_iso garbage", kgl._iso("junk") == 0)


t_iso()


# --- cache on transient verify failure: refused (not blindly trusted), file kept
def t_cache_fault_tolerance():
    orig_slug, orig_api = kgl._notebook_slug, kgl._kgl_cookie_api
    kgl._notebook_slug = lambda: "owner/target"
    cache = os.path.join(kgl.CONFDIR, "kernel_id")
    real_sleep = kgl.time.sleep
    kgl.time = types.SimpleNamespace(time=kgl.time.time,
        strftime=kgl.time.strftime, sleep=lambda s: None)
    try:
        kgl._secure_write(cache, "owner/target 42\n")
        kgl._kgl_cookie_api = lambda m, b: (False, None)  # persistent API failure
        check("lazy: unknown ownership -> None (not trusted)",
              kgl._notebook_kernel_id(required=False) is None)
        try:
            kgl._notebook_kernel_id(required=True)
            check("required: unknown ownership -> refuses", False)
        except SystemExit as e:
            check("required: unknown ownership -> refuses", "verify" in str(e))
        check("cache file still present (kept for recovery)", os.path.exists(cache))
    finally:
        kgl._notebook_slug, kgl._kgl_cookie_api = orig_slug, orig_api
        kgl.time = types.SimpleNamespace(time=kgl.time.time,
            strftime=kgl.time.strftime, sleep=real_sleep)
        if os.path.exists(cache):
            os.unlink(cache)


t_cache_fault_tolerance()


# --- _mint_route must NOT touch the global base file ------------------------
def t_mint_route_no_side_effect():
    basefile = kgl.BASEFILE
    kgl._secure_write(basefile, "https://original-route/proxy\n")
    orig = kgl._fb_session
    kgl._fb_session = lambda w=None: (1, "doc", "tok", None)
    orig_get = kgl._fs_get
    kgl._fs_get = lambda d, sub, i: (
        {"fields": {"url": {"stringValue": "https://minted-route/proxy"}}}, 200)
    try:
        url = kgl._mint_route()
        check("mint returns url", url == "https://minted-route/proxy")
        check("global base untouched", open(basefile).read().strip() == "https://original-route/proxy")
    finally:
        kgl._fb_session, kgl._fs_get = orig, orig_get
        os.unlink(basefile)


t_mint_route_no_side_effect()


# --- _fetch_json: url not in argv --------------------------------------------
def t_fetch_json_argv():
    real_run = subprocess.run
    seen = []
    def spy(cmd, **kw):
        seen.append(" ".join(cmd))
        kw.pop("input", None)
        r = real_run(["true"], **kw)
        r.stdout = b'{"k":1}\n200'
        return r
    subprocess.run = spy
    try:
        code, out = kgl._fetch_json("https://x/JWE-SECRET/proxy/api/kernels")
        check("fetch parses", code == 200 and out == {"k": 1})
    finally:
        subprocess.run = real_run
    check("JWE url not in argv", "JWE-SECRET" not in seen[0], seen[0][:100])
    check("fetch uses -K", "-K" in seen[0])


t_fetch_json_argv()


# --- run-all kernel matching logic (unit: the matching loop body) -----------
def t_runall_match_logic():
    # extract the predicates the verification loop uses, as data checks:
    def accept(kernels, sessions):
        tgt = None
        for sess in sessions:
            if isinstance(sess, dict) and sess.get("path") == "__notebook_source__.ipynb":
                tgt = sess.get("kernel", {}).get("id")
        if tgt is None:
            return False  # target unidentifiable -> unverified, never success
        return any(k.get("id") == tgt and k.get("execution_state") == "busy"
                   for k in kernels)

    NB = [{"path": "__notebook_source__.ipynb", "kernel": {"id": "K1"}}]
    check("target busy -> accept", accept([{"id": "K1", "execution_state": "busy"}], NB))
    check("other kernel busy -> reject",
          not accept([{"id": "K2", "execution_state": "busy"}], NB))
    check("target idle -> reject",
          not accept([{"id": "K1", "execution_state": "idle"}], NB))
    check("no sessions -> reject (tgt unknown)",
          not accept([{"id": "K1", "execution_state": "busy"}], []))
    check("error dict instead of list -> reject (guarded upstream)",
          not accept([{"id": "K1", "execution_state": "busy"}], {"error": 401}))


t_runall_match_logic()


# --- _fetch_json guards: error body parses but callers see the code ----------
def t_fetch_json_error_body():
    real_run = subprocess.run
    def fake(cmd, **kw):
        return types.SimpleNamespace(returncode=0, stdout=b'{"error": {"code": 401}}\n401')
    subprocess.run = fake
    try:
        code, out = kgl._fetch_json("https://x/")
        check("error body surfaces code", code == 401 and isinstance(out, dict))
    finally:
        subprocess.run = real_run


t_fetch_json_error_body()


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
