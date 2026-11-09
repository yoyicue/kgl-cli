# kgl-cli

> **Unofficial** — uses Kaggle's internal (reverse-engineered) APIs. Not affiliated with Kaggle/Google; could break anytime; respect their ToS and GPU quotas.

Control a running Kaggle notebook sandbox (Jupyter) from your local terminal — pure HTTP, no browser required after initial login.

## How it works

Kaggle's notebook editor embeds JupyterLab behind a proxy at
`kkb-production.jupyter-proxy.kaggle.net/k/{runId}/{JWE}/proxy`. `kgl bootstrap`
mints that route via Firebase (reverse-engineered chain), then exec/sh/get/put
talk to the Jupyter REST + kernel websocket APIs directly.

```
kaggle cookies ─▶ GetFirebaseAuthToken ─▶ signInWithCustomToken (kkb-production)
              ─▶ UpdateUserKernelFirestoreAuth ─▶ Firestore: sessions/<doc>/data/JupyterURL
```

## Install

```bash
ln -s ~/kgl/kgl ~/.local/bin/kgl
pip3 install --user --break-system-packages websocket-client   # only dep
```

## Usage

```bash
kgl bootstrap [title|kernelRunId]   # mint /k/ route (pure HTTP, ~3s)
kgl watch [sel] [--interval N] [--once]  # poll Firestore: session death/GPU idle alerts
kgl session stop|run-all|save       # browser-gated actions via headless chrome
kgl status                          # kernel + terminal state
kgl exec "python code"              # run python in the kernel
kgl sh "shell command"              # run shell; exit code preserved
kgl get remote.txt [local]          # download (text/json/base64)
kgl put local remote                # upload (auto-mkdir parents)
```

- Multiple sessions: `kgl bootstrap "Tesla"` or `kgl bootstrap 367184647` — refuses to guess.
- Cookie refresh: re-login to kaggle in any chrome with `--remote-debugging-port=9222`;
  `kgl bootstrap` picks them up and caches (verified against the API first).
- `kgl term` is unsupported: Kaggle blocks the terminado websocket. Use `sh`/`exec`.

## Config & secrets

`~/.config/kgl/` (0700): `cookies.json`, `base` (live credentials, 0600),
`notebook` (last slug). Credentials are passed to curl via 0600 config files
and stdin, never argv.

## How the route mint was found

Short version: the editor page passes a proxy URL (with an encrypted token)
down to its JupyterLab iframe; that URL actually lives in a Firestore document
(`sessions/<doc>/data/JupyterURL`), reachable after a three-step auth chain.
`kgl bootstrap` replays that chain with plain HTTP calls. See git history for
the full adventure.

## Test

```bash
python3 test_kgl.py   # offline unit tests (no network, mocks curl)
```

## License

MIT — see [LICENSE](LICENSE).

## Known limits

- `sh` decodes output as UTF-8; invalid bytes → replacement chars + warning.
  Byte-exact transfer: `kgl put` a script, `kgl sh` it, `kgl get` the file.
- Session must be RUNNING (run a cell once in the web editor).
