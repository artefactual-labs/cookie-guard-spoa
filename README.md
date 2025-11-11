# cookie-guard-spoa

`cookie-guard-spoa` is an HAProxy SPOE (Stream Processing Offload Engine) agent that issues and validates HMAC‑signed cookies.

It ships with a privacy‑friendly browser challenge powered by ALTCHA and dedicated endpoints built into the agent. HAProxy serves a small HTML page and the agent verifies the puzzle solution, issuing the `hb_v2` cookie on success. Only clients presenting a valid cookie reach your backend.

Learn more about ALTCHA:

- Website: https://altcha.org
- JavaScript library (open source): https://github.com/altcha-org/altcha
- Go library used here: https://github.com/altcha-org/altcha-lib-go
- Example starter (Go): https://github.com/altcha-org/altcha-starter-go

---


## Overview

The agent offloads cookie lifecycle management from HAProxy:

1. Generates short-lived, signed cookies derived from the client IP and User-Agent.
2. Exposes helper endpoints that HAProxy can embed in a challenge page.
3. Validates cookies on subsequent requests and reports the outcome back to HAProxy via SPOE frames.
4. Enables HAProxy to allow, rate-limit, or block requests that fail the validation.

This setup filters out most headless bots, generic scanners, or curl-based tooling that cannot execute JavaScript or persist cookies.

---

## Features

- Stateless HMAC cookie generation and verification.
- Built‑in ALTCHA support with first‑party endpoints (`/altcha-challenge`, `/altcha-verify`).
- Privacy‑friendly alternative to CAPTCHAs; no trackers or external calls required.
- Pure Go binary with no external runtime dependencies.
- Secret key hot-reload via `SIGHUP`.
- Local-only TCP listener; TLS is not required for the SPOE link.
- Built-in health and Prometheus metrics endpoints.
- Plays well with other SPOEs such as `geoip-spoa` or `coraza-spoa`.

---

## Build from source

```bash
git clone https://github.com/artefactual-labs/cookie-guard-spoa.git
cd cookie-guard-spoa

# Ensure Go ≥ 1.25.3
go mod tidy
make
```

Output:
```
bin/cookie-guard-spoa
```

---

## Installation (manual)

1. **Create secret**
   ```bash
   sudo install -d -m0750 /etc/cookie-guard-spoa
   sudo head -c 48 /dev/urandom | base64 > /etc/cookie-guard-spoa/secret.key
   sudo chmod 0640 /etc/cookie-guard-spoa/secret.key
   ```

2. **Install binary and service**
   ```bash
   sudo install -m0755 bin/cookie-guard-spoa /usr/local/bin/cookie-guard-spoa
   sudo cp systemd/cookie-guard-spoa.service /etc/systemd/system/
   sudo install -D -m0644 packaging/default/cookie-guard-spoa /etc/default/cookie-guard-spoa
   sudo install -D -m0644 haproxy/cookie-guard-spoa.cfg /etc/haproxy/cookie-guard-spoa.cfg
   sudo systemctl daemon-reload
   sudo systemctl enable --now cookie-guard-spoa
   ```

3. **Verify**
   ```bash
   curl -sf http://127.0.0.1:9904/healthz
   # → ok
   ```

---

## Packages

Official `.deb` and `.rpm` packages are published alongside each GitHub release. Installing one of these packages will:

- Place the binary in `/usr/local/bin/cookie-guard-spoa`.
- Install the systemd unit at `/etc/systemd/system/cookie-guard-spoa.service`.
- Create `/etc/cookie-guard-spoa/` (group-owned by `haproxy` when present) and seed a random `secret.key` if none exists.
- Enable and start the service automatically (requires systemd).
- Drop default CLI options in `/etc/default/cookie-guard-spoa` (edit to customize runtime flags; `-debug` is not enabled by default).
- Place an HAProxy SPOE snippet at `/etc/haproxy/cookie-guard-spoa.cfg`.
- When SELinux is enforcing, allow TCP ports `9903` and `9904` for the service.

Additionally, packages include the challenge pages and ALTCHA assets under `/etc/haproxy/`:

- `/etc/haproxy/altcha_challenge.html.lf`.
- ALTCHA JS is installed under `/etc/haproxy/assets/altcha/<version>/altcha.min.js[.lf]` with `/etc/haproxy/assets/altcha/active` symlink updated to the packaged version.

After installation, adjust `/etc/cookie-guard-spoa/secret.key` or edit the systemd unit as needed, then `systemctl restart cookie-guard-spoa`.

To change command-line flags, edit `/etc/default/cookie-guard-spoa`. This file uses a base `COOKIE_GUARD_SPOA_OPTS` plus simple toggles you can uncomment:

```bash
# /etc/default/cookie-guard-spoa (snippets)
COOKIE_GUARD_SPOA_OPTS="-listen 127.0.0.1:9903 -metrics 127.0.0.1:9904 -secret /etc/cookie-guard-spoa/secret.key -ttl 1h -skew 30s -altcha-assets /etc/haproxy/assets/altcha -altcha-page /etc/haproxy/altcha_challenge.html.lf -altcha-expires 2m"
# Enabled by default in packages:
COOKIE_GUARD_FLAG_COOKIE_SECURE="-cookie-secure"
# Optional toggles:
#COOKIE_GUARD_FLAG_DEBUG="-debug"
#COOKIE_GUARD_FLAG_ALTCHA_DISABLE="-altcha=false"
#COOKIE_GUARD_FLAG_EXTRA=""
```

After editing, run `systemctl restart cookie-guard-spoa`.

---

## HAProxy integration

1. **SPOE engine definition** (`/etc/haproxy/cookie-guard.cfg`)

   ```ini
   [spoe]
   max-frame-size 16384
   max-waiting-frames 2000

   agent cookie_guard
       use-backend cookie_guard_backend
       messages issue-token verify-token
       option pipelining
       timeout hello      2s
       timeout idle       30s
       timeout processing 2s

   message issue-token
       args src-ip=ip.src ua="req.fhdr(User-Agent)"

   message verify-token
       args src-ip=ip.src ua="req.fhdr(User-Agent)" cookie=req.cook(hb_v2)
   ```

2. **Backend connection**

   ```haproxy
   backend cookie_guard_backend
       mode tcp
       server spoa1 127.0.0.1:9903 check
   ```

3. **Example application backend**

   ```haproxy
   backend be_app
       option http-buffer-request

       acl chal_safe_meth method GET HEAD
       acl chal_exempt_path path_beg -i /health /status /static/ /favicon.ico
       acl chal_exempt_cookie req.cook(hb_v2) -m found
       acl chal_target chal_safe_meth !chal_exempt_path

       http-request set-spoe-group cookie_guard verify-token if chal_target chal_exempt_cookie
       acl cookie_ok var(txn.cookie_guard.valid) -m str 1

       http-request set-spoe-group cookie_guard issue-token if chal_target !cookie_ok

       server app1 127.0.0.1:8080 check
   ```

   When HAProxy runs the `verify-token` message, the agent populates the following transaction-scoped variables (prefixed via `option var-prefix cookieguard`):

   - `txn.cookieguard.valid`: `"1"` when the hb_v2 cookie validates, otherwise `"0"`.
   - `txn.cookieguard.age_seconds`: age of the accepted cookie (stringified integer seconds).
   - `txn.cookieguard.session_hmac`: HMAC handle derived from the cookie value for downstream session tracking (empty when invalid or missing).
   - `txn.cookieguard.challenge_level`: textual label for the challenge that produced the cookie (currently `"altcha"` for hb_v2).

## SPOE inputs and outputs

The agent exchanges two SPOE messages with HAProxy: `issue-token` (fires when a client needs a new cookie) and `verify-token` (fires to validate an existing cookie). Each message has a small, well-defined contract:

### Inputs (message arguments)

| Message | Arg | Required | Description |
| --- | --- | --- | --- |
| `issue-token` | `src-ip` | yes | Client IP used to bind and sign the issued token. Pass either `ip.src` (L4) or a header-derived value that reflects the real client. |
| `issue-token` | `ua` or `ua_sha1` | optional | User-Agent binding. Provide the full header via `req.fhdr(User-Agent)` or a pre-hashed SHA-1 (hex, lower-case) in `ua_sha1`. When omitted the agent hashes the provided `ua`; disable binding entirely via `-ua-bind=false`. |
| `verify-token` | `src-ip` | yes | Must match the IP used at issuance so the token layout check and signature succeed. |
| `verify-token` | `ua` or `ua_sha1` | optional | Same semantics as on issuance; using `ua_sha1` avoids re-hashing in the agent. |
| `verify-token` | `cookie` | yes | The raw `hb_v2` cookie value (e.g. `req.cook(hb_v2)`). Tokens longer than 8 KB or not matching the expected format are rejected early.

All inputs beyond those listed are ignored. If you cannot provide a reliable `ua`, set `-ua-bind=false` so the agent automatically treats the UA hash as empty.

### Outputs (transaction variables)

With `option var-prefix cookieguard`, HAProxy sees the following variables under `var(txn.cookieguard.<name>)`:

- `token` (string, optional): set by `issue-token` when a fresh cookie was minted. Empty when issuance fails or is skipped; typically used to write `Set-Cookie` headers inside HAProxy.
- `max_age` (integer-as-string, optional): TTL in seconds paired with `token`. Only meaningful when `token` is non-empty.
- `valid` (`"1"`/`"0"`, always set by `verify-token`): indicates whether the presented cookie passed validation. Useful for quick ACLs (`var(txn.cookieguard.valid) -m str 1`).
- `age_seconds` (stringified integer, always set): age of the accepted cookie. Remains "0" for invalid/missing cookies. You can rate-limit or log based on freshness.
- `session_hmac` (hex string, optional): deterministic HMAC derived from the hb_v2 payload. Decision-SPOA uses this value as `cookieguard_session` to correlate sessions without exposing the token itself. Empty when validation fails.
- `challenge_level` (string, optional): label describing how the cookie originated. Currently always `"altcha"` when verification succeeds; keep space for future challenge types.

By design, `verify-token` always resets every output to a safe default before attempting validation so stale data never leaks between transactions.

4. **ALTCHA challenge (default)**

   ALTCHA is the recommended challenge. The agent exposes two endpoints on the metrics HTTP port when `-altcha` is enabled (default: on):

   - `GET /altcha-challenge` — issues a short‑lived puzzle
   - `POST /altcha-verify` — verifies the client’s solution and, on success, sets the `hb_v2` cookie

   HAProxy routing example (frontend):

   ```haproxy
   # Route ALTCHA page, verify, and JS to the agent’s HTTP listener
   acl altcha_routes path_beg -i /altcha /altcha- /assets/altcha/
   use_backend cookie_guard_http_backend if altcha_routes
   ```

   Backend used above (already provided in `haproxy/cookie-guard-spoa.cfg`):

   ```haproxy
   backend cookie_guard_http_backend
       mode http
       option forwarded
       option forwardfor
       # Ensure agent sees the same client IP HAProxy will use later
       http-request set-header X-Forwarded-For %[src]
       server spoa_http 127.0.0.1:9904 check
   ```

   Notes:
   - Place `web/altcha_challenge.html.lf` at `/etc/haproxy/altcha_challenge.html.lf`.
   - Vendor and install versioned ALTCHA assets under `/etc/haproxy/assets/altcha/<version>/altcha.min.js` and keep a stable symlink `/etc/haproxy/assets/altcha/active -> <version>`.
   - This repo includes helpers to fetch and stage assets locally:
     ```bash
     # Set desired ALTCHA JS tag (from altcha releases) and sync
     echo v2.5.0 > web/assets/altcha/VERSION
     make altcha-assets

     # Install to HAProxy's path
     sudo make install-altcha-assets
     ```
   - The HTML references `/assets/altcha/active/altcha.min.js`. The agent serves this path from `-altcha-assets` (default `/etc/haproxy/assets/altcha`) to avoid HAProxy buffer limits.
   - The agent also serves the page at `/altcha` from `-altcha-page` (default `/etc/haproxy/altcha_challenge.html.lf`).
   - Packages enable `-cookie-secure` by default so `hb_v2` ships with the `Secure` attribute. Comment it in `/etc/default/cookie-guard-spoa` if you must disable it.

 

6. **Frontend**

   ```haproxy
   frontend fe_edge
       bind :80
       default_backend be_app
   ```

---

## Local test

```bash
# First request (no cookie): challenge page
curl -i http://localhost/ --cookie-jar /tmp/cookies.txt

# Second request (with cookie): should reach backend
curl -i http://localhost/ --cookie /tmp/cookies.txt
```

Add the temporary line below to confirm validation during development:

```haproxy
http-response add-header X-CookieGuard-Valid %[var(txn.cookie_guard.valid)]
```

---

### Debug logging

Enable verbose traces of issued and verified cookies when developing:

```bash
./bin/cookie-guard-spoa -listen 127.0.0.1:9903 -metrics 127.0.0.1:9904 -secret /etc/cookie-guard-spoa/secret.key -ttl 1h -debug
```

The agent logs why cookies are accepted or rejected; disable `-debug` in production to avoid noisy logs.

### Update ALTCHA

To update the ALTCHA JavaScript asset and Go library in a controlled way:

- JS asset (served by HAProxy):
  ```bash
  echo vX.Y.Z > web/assets/altcha/VERSION    # pick a release tag from altcha
  make altcha-assets                         # fetches to web/assets/altcha/<version>/ and updates 'active'
  sudo make install-altcha-assets            # installs under /etc/haproxy/assets/altcha/
  systemctl reload haproxy                   # start serving the new asset
  ```
- Go library (used by the agent):
  ```bash
  make altcha-go-bump VERSION=vA.B.C
  go mod tidy
  make
  sudo systemctl restart cookie-guard-spoa
  ```

ALTCHA-specific flags:

- `-altcha` (default: true) enable/disable the ALTCHA challenge and verify endpoints.
- `-altcha-expires` (default: 2m) lifetime of issued challenges.
- `-cookie-secure` add the `Secure` attribute to `hb_v2` set by `/altcha-verify`.
- `-altcha-assets` base directory for vendored JS; serves `/assets/altcha/active/altcha.min.js`.
- `-altcha-page` path to the HTML page served at `/altcha`.

Versioning policy and updates:

- Go library: pinned in `go.mod` as `github.com/altcha-org/altcha-lib-go @ vX.Y.Z`. Bump with:
  ```bash
  go get github.com/altcha-org/altcha-lib-go@vX.Y.Z
  go mod tidy
  ```
- JS asset: pinned by directory name under `web/assets/altcha/<version>` and by the `VERSION` file. Bump with:
  ```bash
  echo vX.Y.Z > web/assets/altcha/VERSION
  make altcha-assets
  sudo make install-altcha-assets
  systemctl reload haproxy
  ```

---

## Security notes

- Keep the secret key (`/etc/cookie-guard-spoa/secret.key`) private and stable across restarts.
- Reload the service to pick up a new key:
  ```bash
  systemctl kill -s HUP cookie-guard-spoa
  ```
- Run the service as a non-privileged user (for example `nobody:nogroup`).
- Bind to `127.0.0.1`; the SPOE link does not need TLS.

---

## Health and Metrics

The service exposes `127.0.0.1:9904` by default with:

| Endpoint   | Description                                  | Example                                      |
|------------|----------------------------------------------|----------------------------------------------|
| `/healthz` | Health check — returns “ok”                  | `curl -sf http://127.0.0.1:9904/healthz`     |
| `/metrics` | Prometheus metrics with counters/histograms | `curl -sf http://127.0.0.1:9904/metrics`     |

Example snippet:

```
# HELP cookie_guard_issue_total Total number of issued challenge tokens
# TYPE cookie_guard_issue_total counter
cookie_guard_issue_total 42
# HELP cookie_guard_verify_total Total number of verify requests
# TYPE cookie_guard_verify_total counter
cookie_guard_verify_total 41
# HELP cookie_guard_verify_outcome_total Verify outcomes by result
# TYPE cookie_guard_verify_outcome_total counter
cookie_guard_verify_outcome_total{outcome="valid"} 40
cookie_guard_verify_outcome_total{outcome="invalid"} 1
# HELP cookie_guard_handler_seconds Time spent handling SPOE messages
# TYPE cookie_guard_handler_seconds histogram
cookie_guard_handler_seconds_sum{message="issue-token"} 0.072
cookie_guard_handler_seconds_count{message="issue-token"} 42
```

Scrape these metrics from Prometheus or query them directly during debugging.

---

## Directory structure

```
.
├── cmd/cookie-guard-spoa/      # main Go entrypoint
├── systemd/cookie-guard-spoa.service # systemd unit
├── haproxy/js-spoe.cfg         # SPOE config snippet
├── packaging/                  # am-packbuild manifests
├── bin/                        # compiled binaries (ignored in git)
└── dist/                       # built packages (ignored in git)
```

---

## Development

- Reload the secret without restart:
  ```bash
  systemctl kill -s HUP cookie-guard-spoa
  ```
- Debug HAProxy integration:
  ```bash
  haproxy -d -f /etc/haproxy/haproxy.cfg
  ```
- Clean builds:
  ```bash
  make clean && make
  ```
- Check metrics during development:
  ```bash
  curl -sf http://127.0.0.1:9904/healthz
  curl -sf http://127.0.0.1:9904/metrics | grep cookie_guard_
  ```
 
