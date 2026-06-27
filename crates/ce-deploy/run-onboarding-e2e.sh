#!/usr/bin/env bash
# Automated real-VM onboarding E2E. Provisions fresh Hetzner VMs, runs the developer install+connect
# flow, asserts sync/deploy, tears down. One command:  ./run-onboarding-e2e.sh
# Needs HETZNER_API_TOKEN, CE_SSH_KEY_NAME, CE_SSH_KEY_PATH (auto-sourced from ce/.env if present).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
[ -f "$ROOT/.env" ] && { set -a; . "$ROOT/.env"; set +a; }
export CE_SSH_KEY_PATH="${CE_SSH_KEY_PATH/#\~/$HOME}"
: "${HETZNER_API_TOKEN:?set HETZNER_API_TOKEN}"; : "${CE_SSH_KEY_NAME:?}"; : "${CE_SSH_KEY_PATH:?}"
echo "Running real-VM onboarding E2E (Hetzner: $CE_SSH_KEY_NAME)..."
exec cargo test -p ce-deploy --test onboarding_e2e -- --ignored --nocapture --test-threads=1
