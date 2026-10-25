#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if systemctl --user is-active --quiet secclaw-discovery.service; then
  echo "SecClaw discovery worker is already running."
  exit 0
fi

systemctl --user reset-failed secclaw-discovery.service 2>/dev/null || true
systemd-run --user --unit=secclaw-discovery \
  --description="SecClaw mDNS discovery worker" \
  --property=Restart=always --property=RestartSec=5 \
  --working-directory="$repo_root/web" \
  /usr/bin/node "$repo_root/web/scripts/discovery-worker.mjs"
