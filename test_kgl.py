#!/usr/bin/env python3
"""Offline unit tests for kgl internals — no network, curl is mocked.

Run: python3 test_kgl.py
"""
import json, os, subprocess, sys, tempfile, types

# import kgl as module (skip main())
SRC = open(os.path.join(os.path.dirname(__file__), "kgl")).read()
SRC = SRC.replace('if __name__ == "__main__":\n    main()', '')
kgl = types.ModuleType("kgl")
exec(compile(SRC, "kgl", "exec"), kgl.__dict__)

TMP = tempfile.mkdtemp()
FAILS = []


def check(name, cond, detail=""):
    print(("PASS" if cond else "FAIL"), name, detail if not cond else "")
    if not cond:
        FAILS.append(name)


# --- fixtures ------------------------------------------------------------
GOOD_COOKIES = [
    {"name": "XSRF-TOKEN", "value": "xsrf123", "domain": ".kaggle.com",
     "path": "/", "secure": True},
    {"name": "ka_sessionid", "value": "sess456", "domain": ".kaggle.com",
     "path": "/", "secure": True},
]
NO_XSRF = [{"name": "ka_sessionid", "value": "x", "domain": ".kaggle.com",
            "path": "/", "secure": True}]


def with_cookies(cookies, fn):
    """Run fn with cookiefile swapped to fixture."""
    cf = os.path.join(TMP, "cookies.json")
    old = kgl.BASEFILE
    json.dump(cookies, open(cf, "w"))
    kgl_cookiefile = os.path.join(kgl.CONFDIR, "cookies.json")
    # monkeypatch _cookie_store's file location via CONFDIR
    orig_confdir = kgl.CONFDIR
    kgl.CONFDIR = TMP
    try:
        return fn()
    finally:
        kgl.CONFDIR = orig_confdir


# --- 1. XSRF missing -> clear error, not IndexError ----------------------
def t_missing_xsrf():
    try:
        with_cookies(NO_XSRF, lambda: kgl.bootstrap())
        check("xsrf-missing exits", False)
    except SystemExit as e:
        check("xsrf-missing exits", True)
        check("xsrf-missing message actionable",
              "XSRF" in str(e) and "re-login" in str(e), str(e))


t_missing_xsrf()


# --- 2. session selection -------------------------------------------------
SESSIONS = [
    {"kernelRunId": 111, "title": "Tesla_T4x2", "dateCreated": "2026-11-09T01:00:00Z"},
    {"kernelRunId": 222, "title": "My CPU nb", "dateCreated": "2026-11-09T02:00:00Z"},
]

def t_session_pick():
    with_cookies(GOOD_COOKIES, lambda: None)  # ensure cookiefile exists
    try:
        _pick(SESSIONS, None)
        check("two-sessions refuses", False)
    except SystemExit:
        check("two-sessions refuses", True)

    check("by title substring", _pick(SESSIONS, "tesla") == 111)
    check("by runId", _pick(SESSIONS, "222") == 222)
    check("single auto", _pick(SESSIONS[:1], None) == 111)
    try:
        _pick(SESSIONS, "no-match")
        check("unknown refuses", False)
    except SystemExit:
        check("unknown refuses", True)

def _pick(sessions, which):
    """Mirror of bootstrap's selection logic (kept in sync manually)."""
    if which:
        cand = [s for s in sessions
                if which.isdigit() and str(s["kernelRunId"]) == which
                or which.lower() in s.get("title", "").lower()]
    else:
        cand = sessions if len(sessions) == 1 else []
    if len(cand) != 1:
        raise SystemExit("ambiguous")
    return cand[0]["kernelRunId"]

t_session_pick()


# --- 3. _auth_err classification ------------------------------------------
def t_auth_err():
    m = kgl._auth_err(403, None)
    check("403 -> re-login hint", "re-login" in m, m)
    m = kgl._auth_err(0, "boom")
    check("0 -> network", "network" in m, m)
    m = kgl._auth_err(500, {"error": "x"})
    check("500 surfaces code", "500" in m, m)

t_auth_err()


# --- 4. _secure_write permissions -----------------------------------------
def t_secure_write():
    p = os.path.join(TMP, "sec")
    kgl._secure_write(p, "secret")
    mode = os.stat(p).st_mode & 0o777
    check("secure write 0600", mode == 0o600, oct(mode))
    check("secure write content", open(p).read() == "secret")

t_secure_write()


# --- 5. _post_json: credentials not in argv -------------------------------
def t_post_json_argv():
    real_run = subprocess.run
    seen_argv = []

    def spy_run(cmd, **kw):
        seen_argv.append(cmd)
        return real_run(["true"], **{"capture_output": True, "input": b""})

    subprocess.run = spy_run
    try:
        kgl._post_json("https://x/", {}, {"cookie": "SECRETVALUE", "Authorization": "Bearer TOK"})
    finally:
        subprocess.run = real_run
    joined = " ".join(seen_argv[0]) if seen_argv else ""
    check("no secret in argv", "SECRETVALUE" not in joined and "TOK" not in joined, joined[:120])
    check("uses -K config", any(a == "-K" for a in seen_argv[0]) if seen_argv else False)

t_post_json_argv()


# --- 6. _post_json parsing with mock curl ----------------------------------
def t_post_json_parse():
    real_run = subprocess.run
    RESP = b'{"ok": true}\n200'

    def fake_run(cmd, **kw):
        class R: returncode = 0; stdout = RESP
        return R()

    subprocess.run = fake_run
    try:
        code, out = kgl._post_json("https://x/", {}, {})
        check("parses code", code == 200)
        check("parses body", out == {"ok": True})
    finally:
        subprocess.run = real_run

t_post_json_parse()


print()
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("all tests passed")
