# js-cookie-challenge-spoa

**HAProxy SPOE agent implementing a JavaScript cookie challenge** to detect and throttle non-browser traffic (bots, scrapers, etc.) before requests reach your backend.

This service works together with HAProxy to:
- Issue **HMAC-signed cookies** for browsers that execute JavaScript.
- Verify the cookie on subsequent requests.
- Reject or rate-limit clients that cannot execute JavaScript or set cookies.
- Integrate with other SPOEs such as `geoip-spoa` or `coraza-spoa`.

---

## Overview

`js-cookie-challenge-spoa` is a lightweight Go service that communicates with HAProxy over the **SPOE (Stream Processing Offload Engine)** protocol.

It:
1. Generates short-lived, signed tokens (HMAC SHA-256) based on the client IP and User-Agent.
2. Embeds the token in a small JavaScript snippet served by HAProxy.
3. On reload, the browser sends back the cookie, which HAProxy verifies via the SPOE agent.
4. Only verified requests reach your backend servers.

This effectively blocks:
- Headless bots and scrapers without JavaScript/cookie support.
- Most generic scanners and curl-based tools.

---

## ⚙️ Features

- Pure Go binary (no runtime or virtualenv)
- **Single secret file** for signing tokens
- **HUP reload** of secret key
- Localhost-only TCP (no TLS needed)
- Built-in `/healthz` endpoint
- Works on **HTTP or HTTPS** frontends
- Packaged for Debian/Ubuntu and RHEL/Rocky via **[am-packbuild](https://github.com/artefactual-labs/am-packbuild)**

---

## Build from source

```bash
git clone https://github.com/artefactual-labs/js-cookie-challenge-spoa.git
cd js-cookie-challenge-spoa

# Ensure Go ≥ 1.21
go mod tidy
make

