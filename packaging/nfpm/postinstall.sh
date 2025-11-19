#!/bin/sh
set -e

SERVICE="cookie-guard-spoa.service"
SECRET_DIR="/etc/cookie-guard-spoa"
SECRET_FILE="$SECRET_DIR/secret.key"
GROUP="haproxy"

if getent group "$GROUP" >/dev/null 2>&1; then
  SECRET_GROUP="$GROUP"
else
  SECRET_GROUP="root"
fi

install -d -m0750 -o root -g "$SECRET_GROUP" "$SECRET_DIR"

if [ ! -f "$SECRET_FILE" ]; then
  head -c 48 /dev/urandom | base64 > "$SECRET_FILE"
  chmod 0640 "$SECRET_FILE"
  chown root:"$SECRET_GROUP" "$SECRET_FILE"
fi

if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled >/dev/null 2>&1; then
  if command -v semanage >/dev/null 2>&1; then
    for PORT in 9903 9904; do
      semanage port -a -t http_port_t -p tcp "$PORT" >/dev/null 2>&1 || \
        semanage port -m -t http_port_t -p tcp "$PORT" >/dev/null 2>&1 || true
    done
  fi
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now "$SERVICE" >/dev/null 2>&1 || true
fi

# Ensure ALTCHA assets symlink points to packaged version, if present
ALTCHA_DIR="/etc/haproxy/assets/altcha"
if [ -f "$ALTCHA_DIR/VERSION" ]; then
  ALTCHA_VER=$(head -n1 "$ALTCHA_DIR/VERSION" 2>/dev/null || true)
  if [ -n "$ALTCHA_VER" ] && [ -d "$ALTCHA_DIR/$ALTCHA_VER" ]; then
    ln -sfn "$ALTCHA_VER" "$ALTCHA_DIR/active"
  fi
fi

# Ensure BotD assets symlink points to packaged version, if present
BOTD_DIR="/etc/haproxy/assets/botd"
if [ -f "$BOTD_DIR/VERSION" ]; then
  BOTD_VER=$(head -n1 "$BOTD_DIR/VERSION" 2>/dev/null || true)
  if [ -n "$BOTD_VER" ] && [ -d "$BOTD_DIR/$BOTD_VER" ]; then
    ln -sfn "$BOTD_VER" "$BOTD_DIR/active"
  fi
fi

exit 0
