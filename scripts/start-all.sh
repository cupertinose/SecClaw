#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

docker compose up --detach --build postgres web scanner
"$repo_root/scripts/start-discovery.sh"
docker compose ps
