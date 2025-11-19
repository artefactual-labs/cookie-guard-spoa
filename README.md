# cookie-guard-spoa

`cookie-guard-spoa` is an HAProxy SPOE (Stream Processing Offload Engine) agent that issues and validates HMAC‑signed cookies.

It ships with two first-party protections enabled by default:

- **ALTCHA** – a lightweight, open-source puzzle that proves the visitor can execute JavaScript, persist cookies, and solve a human-friendly challenge before the origin ever sees the request.
- **BotD (FingerprintJS)** – a local copy of the BotD detector that fingerprints the browser for automation traits (headless Chrome, Selenium drivers, emulators) and reports the verdict back to Cookie Guard, allowing HAProxy or downstream SPOEs to block, throttle, or log suspect sessions.

HAProxy serves a small HTML page that embeds both protections. The agent verifies the ALTCHA solution, ingests the BotD verdict, and issues the `hb_v2` cookie on success. Only clients presenting a valid cookie reach your backend unless you explicitly disable the challenge or BotD via CLI flags.

Learn more about ALTCHA:

- Website: https://altcha.org
- JavaScript library (open source): https://github.com/altcha-org/altcha
- Go library used here: https://github.com/altcha-org/altcha-lib-go
- Example starter (Go): https://github.com/altcha-org/altcha-starter-go

---


## Overview

Cookie Guard inserts an inline checkpoint between HAProxy and your origin that:

1. **Challenges new sessions** – serves the bundled ALTCHA puzzle and locally hosted BotD detector so only browsers that can execute JavaScript, persist cookies, and pass automation fingerprinting obtain an `hb_v2` cookie.
2. **Issues and tracks tokens** – mints short-lived, HMAC-signed cookies bound to the client IP and (optionally) User-Agent, then caches recent BotD verdicts for the same tuple.
3. **Validates on subsequent requests** – verifies hb_v2 on every request via SPOE and reuses the cached BotD verdict so downstream policies can treat “good”, “suspect”, or “bad” sessions differently.
4. **Feeds HAProxy/SPOE peers** – exposes fresh transaction variables (`cookieguard.valid`, `cookieguard.botd_kind`, `cookieguard.session_hmac`, etc.) that HAProxy, Decision-SPOA, or other agents can use to block, rate-limit, or log.

Because the HTML and JavaScript are served from your own HAProxy backend, no third-party calls or trackers are involved. The combination of ALTCHA (prove you are interactive) and BotD (fingerprint automation) removes most headless browsers, cURL scripts, and basic scrapers before they ever see your real site.

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
- BotD JS is installed under `/etc/haproxy/assets/botd/<version>/botd.esm.js[.lf]` with `/etc/haproxy/assets/botd/active` baked into the package so the challenge page can import `/assets/botd/active/botd.esm.js` immediately.

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

### SPOE engine definition (`/etc/haproxy/cookie-guard-spoa.cfg`)

```ini
[cookie-guard]
spoe-agent cookie-guard
    option var-prefix cookieguard
    groups issue-token verify-token
    option pipelining
    timeout hello      2s
    timeout idle       30s
    timeout processing 2s
    use-backend cookie_guard_spoa_backend

spoe-message issue-token
    args src-ip=src ua="req.fhdr(User-Agent)"

spoe-message verify-token
    args src-ip=src ua="req.fhdr(User-Agent)" cookie=req.cook(hb_v2)

spoe-group issue-token
    messages issue-token

spoe-group verify-token
    messages verify-token
```

```haproxy
backend cookie_guard_spoa_backend
    mode tcp
    server spoa1 127.0.0.1:9903 check inter 2s fall 2 rise 1
```

### Reference frontend/backends

Below is a compact `public_www` setup that wires Cookie Guard alone in front of a single backend. Swap the binds/hosts for your environment and layer in additional SPOEs (Decision, Coraza, etc.) later once the basic flow works.

```haproxy
frontend public_www
    bind :80
    bind :443 ssl crt /etc/haproxy/certs/example.pem alpn h2,http/1.1
    option httplog

    # Force HTTPS except for ACME
    acl is_certbot path_beg -i /.well-known/acme-challenge
    http-request redirect scheme https unless { ssl_fc } || is_certbot

    # Cookie Guard: verify hb_v2 only when present
    filter spoe engine cookie-guard config /etc/haproxy/cookie-guard-spoa.cfg
    option http-buffer-request
    acl has_cookie req.cook(hb_v2) -m found
    http-request send-spoe-group cookie-guard verify-token if has_cookie
    acl cookie_ok var(txn.cookieguard.valid) -m str 1

    # Route challenge assets and BotD reports back to the Cookie Guard HTTP listener
    acl altcha_routes path_beg -i /altcha /altcha- /assets/altcha/
    acl botd_path     path -i /botd-report
    acl botd_js       path -i /assets/botd/active/botd.esm.js
    use_backend cookie_guard_http_backend if altcha_routes or botd_path or botd_js

    use_backend certbot if is_certbot
    default_backend app_backend
```

Backends reuse the same Cookie Guard SPOE engine. The snippet below illustrates challenge orchestration plus silent token issuance when Decision (or another policy component) is not involved yet. Feel free to inline your own exemption ACLs.

```haproxy
backend app_backend
    option http-buffer-request

    # Verify hb_v2 only when present
    filter spoe engine cookie-guard config /etc/haproxy/cookie-guard-spoa.cfg
    acl has_cookie req.cook(hb_v2) -m found
    http-request send-spoe-group cookie-guard verify-token if has_cookie
    acl cookie_ok var(txn.cookieguard.valid) -m str 1

    # Simple policy: challenge every request until hb_v2 validates
    acl need_challenge !cookie_ok
    http-request redirect code 302 location /altcha?url=%[url] if need_challenge

    # Auto-issue hb_v2 when you prefer a silent token (e.g., authenticated users)
    http-request send-spoe-group cookie-guard issue-token if !cookie_ok !need_challenge
    acl new_token var(txn.cookieguard.token) -m found
    http-response add-header Set-Cookie "hb_v2=%[var(txn.cookieguard.token)]; Max-Age=%[var(txn.cookieguard.max_age)]; Path=/; HttpOnly; Secure; SameSite=Lax" if !need_challenge !has_cookie new_token

    # Forward headers to your origin
    http-request set-header X-Real-IP %[src]
    http-request add-header X-Forwarded-Proto https if { ssl_fc }
    option forwarded
    option forwardfor
    server app1 127.0.0.1:8080 check
```

Cookie Guard’s HTTP listener serves the ALTCHA HTML, ALTCHA JS, BotD bundle, and `/botd-report`. Route traffic there using:

```haproxy
backend cookie_guard_http_backend
    mode http
    option forwarded
    option forwardfor
    http-request set-header X-Forwarded-For %[src]
    server spoa_http 127.0.0.1:9904 check
```

### What HAProxy gets back

When HAProxy runs the `verify-token` message, the agent populates transaction-scoped variables (prefixed by `option var-prefix cookieguard`):

- `txn.cookieguard.valid`: `"1"` when the hb_v2 cookie validates, otherwise `"0"`.
- `txn.cookieguard.age_seconds`: age of the accepted cookie.
- `txn.cookieguard.session_hmac`: deterministic handle for downstream correlation.
- `txn.cookieguard.challenge_level`: label for the challenge that produced the cookie (`"altcha"` today).
- `txn.cookieguard.botd_*`: BotD verdict metadata (`botd_verdict`, `botd_kind`, `botd_confidence`, `botd_request_id`; `botd_tool` aliases `botd_kind` for legacy rules).

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
- `botd_verdict`/`botd_kind`/`botd_confidence`/`botd_request_id` (strings, optional): populated when a recent BotD report exists for the same client IP + UA hash. `botd_tool` remains as a backward-compatible alias of `botd_kind`. These let [decision-spoa](https://github.com/artefactual-labs/decision-spoa) or native HAProxy ACLs act on BotD detections without re-running the script.

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

5. **BotD verdict ingestion (optional)**

   When `-botd` is enabled (default), the metrics listener exposes `POST /botd-report`. The shipped challenge page loads FingerprintJS BotD in the browser, detects automation, and POSTs the verdict before ALTCHA begins. The payload includes `verdict`, `botKind` (only set when automation is detected), `confidence`, `requestId`, and `ua_hash`. The agent caches each verdict for `-botd-ttl` (default `5m`) keyed by client IP and UA hash, exposes it via SPOE transaction variables (`botd_verdict`, `botd_kind`, `botd_confidence`, `botd_request_id`; `botd_tool` remains as an alias), and emits Prometheus metrics.

   - `botd_confidence` mirrors Fingerprint’s 0–1 confidence score (the bundled OSS detector reports `0` for “no automation observed” and `1` for confirmed bots; the hosted SaaS may emit fractional probabilities).
   - `botd_request_id` surfaces Fingerprint’s request identifier when present, which is useful for correlating detections in their dashboards/logs. Browsers that run entirely locally usually leave it empty.

   - Route `/botd-report` to the same backend that serves `/altcha*` so the agent receives reports.
   - Serve the bundled JS from `/assets/botd/active/botd.esm.js`; packages install it under `/etc/haproxy/assets/botd`, and `make botd-assets && sudo make install-botd-assets` refreshes the version.
   - Enable or disable the endpoint with `-botd`; set cache capacity with `-botd-cache-max` (use `0` to disable storage).
   Prometheus metrics:

   - `cookie_guard_botd_reports_total{verdict="..."}` counts inbound reports.
   - `cookie_guard_botd_cache_entries` shows live cache cardinality.
   - `cookie_guard_botd_cache_evictions_total` increments when entries expire or capacity forces eviction.

   Downstream policy engines (e.g., [decision-spoa](https://github.com/artefactual-labs/decision-spoa)) can read the new SPOE variables to make the final allow/challenge/block decision without changing cookie-guard’s core logic. Cookie Guard focuses on proving “is this a real, interactive browser?” while Decision consumes the resulting `cookieguard.*` and `botd_*` variables (plus GeoIP/session context) to apply richer rules—together they form a layered defense that challenges unknown traffic, fingerprints automation, and then enforces nuanced policies.

## Optional integration with decision-spoa

[decision-spoa](https://github.com/artefactual-labs/decision-spoa) is Artefactual’s policy SPOE for HAProxy. Pairing it with Cookie Guard combines:

- **Cookie Guard** – first-party ALTCHA + BotD challenge, hb_v2 issuance/verification, and BotD verdict caching.
- **Decision** – GeoIP lookups, session-rate tracking, JA3/UA heuristics, and a rule engine that consumes `cookieguard.*` / `botd_*` variables to choose block/allow/challenge routes.

Together they deliver a layered defense: Cookie Guard proves the visitor is an interactive browser and fingerprints automation; Decision ingests those signals plus its own telemetry to decide whether to serve the origin, throttle, or escalate.

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

### Update BotD

- JS asset: pinned under `web/assets/botd/<version>` with `web/assets/botd/active` symlinked to the active version. To bump:
  ```bash
  echo vX.Y.Z > web/assets/botd/VERSION
  make botd-assets
  sudo make install-botd-assets
  systemctl reload haproxy
  ```
- Browser challenge: `web/altcha_challenge.html.lf` imports `/assets/botd/active/botd.esm.js`. Ensure HAProxy routes that path (and `/botd-report`) to the Cookie Guard HTTP listener so the new version is served immediately.

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
 
