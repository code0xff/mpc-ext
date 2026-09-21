#!/usr/bin/env bash
# Runs the release server for local testing with a persistent sealing key.
#
# The key is created on first run and reused afterwards, so wallets survive a restart. It lives
# outside the repository and is for local testing only; never use it for real funds.
#
# Usage: scripts/dev-server.sh            (recovery wait 0 seconds)
#        MPC_SERVER_RECOVERY_COOLING_SECONDS=86400 scripts/dev-server.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
state="${MPC_DEV_STATE_DIR:-$HOME/.mpc-ext-dev}"
key_file="$state/sealing-key"
bin="$root/target/release/mpc-server"

if [[ ! -x "$bin" ]]; then
  echo "error: $bin not found. Run 'make build-server' first." >&2
  exit 1
fi

if [[ ! -f "$key_file" ]]; then
  mkdir -p "$state"
  chmod 700 "$state"
  (umask 077 && openssl rand -hex 32 >"$key_file")
  echo "created a new sealing key at $key_file" >&2
fi

export MPC_SERVER_SEALING_KEY="$(cat "$key_file")"
export MPC_SERVER_RECOVERY_COOLING_SECONDS="${MPC_SERVER_RECOVERY_COOLING_SECONDS:-0}"

exec "$bin"
