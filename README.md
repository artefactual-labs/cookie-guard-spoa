# cookie-guard-spoa

`cookie-guard-spoa` is an HAProxy SPOE (Stream Processing Offload Engine) agent that issues and validates HMAC-signed cookies.  
HAProxy can serve a lightweight JavaScript challenge (or any other mechanism that sets the cookie) and delegate all signing and verification concerns to this service. Only clients presenting a valid cookie reach your backend.

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

# Ensure Go ≥ 1.21
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
   sudo install -d -m0750 /etc/cookie-guard
   sudo head -c 48 /dev/urandom | base64 > /etc/cookie-guard/secret.key
   sudo chmod 0640 /etc/cookie-guard/secret.key
   ```

2. **Install binary and service**
   ```bash
   sudo install -m0755 bin/cookie-guard-spoa /usr/local/bin/cookie-guard-spoa
   sudo cp systemd/cookie-guard-spoa.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now cookie-guard-spoa
   ```

3. **Verify**
   ```bash
   curl -sf http://127.0.0.1:9904/healthz
   # → ok
   ```

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
       args src-ip=ip.src ua=req.hdr(User-Agent),lower

   message verify-token
       args src-ip=ip.src ua=req.hdr(User-Agent),lower cookie=req.cook(hb_v2)
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
       http-request return lf-file /etc/haproxy/js_challenge_v2.html.lf if chal_target !cookie_ok

       server app1 127.0.0.1:8080 check
   ```

4. **Frontend**

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

## Security notes

- Keep the secret key (`/etc/cookie-guard/secret.key`) private and stable across restarts.
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
├── web/js_challenge_v2.html.lf # HTML served by HAProxy
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
