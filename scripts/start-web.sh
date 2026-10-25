#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Compose also starts PostgreSQL because the web service depends on it.
docker compose up --detach --build web
docker compose ps web
