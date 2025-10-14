#!/bin/sh
set -e

SERVICE="cookie-guard-spoa.service"
ACTION="$1"

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  case "$ACTION" in
    remove|purge|0)
      systemctl stop "$SERVICE" >/dev/null 2>&1 || true
      systemctl disable "$SERVICE" >/dev/null 2>&1 || true
      ;;
  esac
fi

exit 0
