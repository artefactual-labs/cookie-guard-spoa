# js-cookie-challenge-spoa

HAProxy SPOE agent implementing a JavaScript cookie challenge to detect and throttle non-browser traffic (bots, scrapers, etc.) before requests reach your backend.

This service works together with HAProxy to:
- Issue HMAC-signed cookies for browsers that execute JavaScript.
- Verify the cookie on subsequent requests.
- Reject or rate-limit clients that cannot execute JavaScript or set cookies.
- Integrate with other SPOEs such as `geoip-spoa` or `coraza-spoa`.

---

## Overview

`js-cookie-challenge-spoa` is a lightweight Go service that communicates with HAProxy over the SPOE (Stream Processing Offload Engine) protocol.

It:
1. Generates short-lived, signed tokens (HMAC SHA-256) based on the client IP and User-Agent.
2. Embeds the token in a small JavaScript snippet served by HAProxy.
3. On reload, the browser sends back the cookie, which HAProxy verifies via the SPOE agent.
4. Only verified requests reach your backend servers.

This effectively blocks:
- Headless bots and scrapers without JavaScript/cookie support.
- Most generic scanners and curl-based tools.

---

## Features

- Pure Go binary (no runtime or virtualenv)
- Single secret file for signing tokens
- SIGHUP reload of secret key
- Localhost-only TCP (no TLS needed)
- Built-in health and metrics endpoints
- Works on HTTP or HTTPS frontends
- Packaged for Debian/Ubuntu and RHEL/Rocky via [am-packbuild](https://github.com/artefactual-labs/am-packbuild)

---

## Build from source

```bash
git clone https://github.com/artefactual-labs/js-cookie-challenge-spoa.git
cd js-cookie-challenge-spoa

# Ensure Go ≥ 1.21
go mod tidy
make
```

Output:
```
bin/js-spoa
```

---

## Installation (manual)

1. Create secret
   ```bash
   sudo install -d -m0750 /etc/js-spoa
   sudo head -c 48 /dev/urandom | base64 > /etc/js-spoa/secret.key
   sudo chmod 0640 /etc/js-spoa/secret.key
   ```

2. Install binary and service
   ```bash
   sudo install -m0755 bin/js-spoa /usr/local/bin/js-spoa
   sudo cp systemd/js-spoa.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now js-spoa
   ```

3. Verify
   ```bash
   curl -sf http://127.0.0.1:9904/healthz
   # → ok
   ```

---

## HAProxy integration

1. SPOE engine definition (`/etc/haproxy/js-spoe.cfg`)

   ```ini
   [spoe]
   max-frame-size 16384
   max-waiting-frames 2000

   agent js
       use-backend js_spoa_backend
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

2. Backend connection

   ```haproxy
   backend js_spoa_backend
       mode tcp
       server spoa1 127.0.0.1:9903 check
   ```

3. Example app backend

   ```haproxy
   backend be_app
       option http-buffer-request

       acl chal_safe_meth method GET HEAD
       acl chal_exempt_path path_beg -i /health /status /static/ /favicon.ico
       acl chal_exempt_cookie req.cook(hb_v2) -m found
       acl chal_target chal_safe_meth !chal_exempt_path

       http-request set-spoe-group js verify-token if chal_target chal_exempt_cookie
       acl cookie_ok var(txn.js.valid) -m str 1

       http-request set-spoe-group js issue-token if chal_target !cookie_ok
       http-request return lf-file /etc/haproxy/js_challenge_v2.html.lf if chal_target !cookie_ok

       server app1 127.0.0.1:8080 check
   ```

4. Frontend

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

You can temporarily add:
```haproxy
http-response add-header X-JS-Valid %[var(txn.js.valid)]
```
to confirm validation.

---

## Security notes

- The secret key (`/etc/js-spoa/secret.key`) must be private and stable across restarts.
- Use SIGHUP to reload a new key:
  ```bash
  systemctl kill -s HUP js-spoa
  ```
- Run the service as a non-privileged user (`nobody:nogroup`).
- Bind to `127.0.0.1` only—no TLS needed for local connections.

---

## Health and Metrics

The service exposes a small HTTP listener (default: `127.0.0.1:9904`) providing:

| Endpoint | Description | Example |
|-----------|--------------|----------|
| `/healthz` | Health check — returns “ok” | `curl -sf http://127.0.0.1:9904/healthz` |
| `/metrics` | Prometheus endpoint with counters and histograms | `curl -sf http://127.0.0.1:9904/metrics` |

### Example `/metrics` output

```
# HELP js_spoa_issue_total Total number of issued challenge tokens
# TYPE js_spoa_issue_total counter
js_spoa_issue_total 42
# HELP js_spoa_verify_total Total number of verify requests
# TYPE js_spoa_verify_total counter
js_spoa_verify_total 41
# HELP js_spoa_verify_outcome_total Verify outcomes by result
# TYPE js_spoa_verify_outcome_total counter
js_spoa_verify_outcome_total{outcome="valid"} 40
js_spoa_verify_outcome_total{outcome="invalid"} 1
# HELP js_spoa_handler_seconds Time spent handling SPOE messages
# TYPE js_spoa_handler_seconds histogram
js_spoa_handler_seconds_sum{message="issue-token"} 0.072
js_spoa_handler_seconds_count{message="issue-token"} 42
# HELP js_spoa_build_info Build information
# TYPE js_spoa_build_info gauge
js_spoa_build_info{version="v1.0.0"} 1
```

You can scrape this from Prometheus or inspect it locally for debugging.

---

## Directory structure

```
.
├── cmd/js-spoa/                # main Go entrypoint
├── systemd/js-spoa.service     # systemd unit
├── haproxy/js-spoe.cfg         # SPOE config snippet
├── web/js_challenge_v2.html.lf # HTML served by HAProxy
├── packaging/                  # am-packbuild manifests
├── bin/                        # compiled binaries (ignored in git)
└── dist/                       # built packages (ignored in git)
```

---

## Development

- Reload secret without restart:
  ```bash
  systemctl kill -s HUP js-spoa
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
  curl -sf http://127.0.0.1:9904/metrics | grep js_spoa_
  ```

