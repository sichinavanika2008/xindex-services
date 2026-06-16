#!/usr/bin/env bash
# Stop the one-box rehearsal: the signer-daemon fleet (up.sh) and anvil
# (up-onchain.sh), if either is running.
set -euo pipefail

out="${XINDEX_REHEARSAL_DIR:-/tmp/xindex-rehearsal}"
pidfile="$out/daemons.pids"
anvilpid="$out/anvil.pid"

if [ -f "$pidfile" ]; then
  while read -r pid; do
    if [ -n "$pid" ] && kill "$pid" 2>/dev/null; then
      echo "stopped daemon $pid"
    fi
  done <"$pidfile"
  rm -f "$pidfile"
else
  echo "no daemon pidfile at $pidfile"
fi

if [ -f "$anvilpid" ]; then
  read -r apid <"$anvilpid" || apid=""
  if [ -n "$apid" ] && kill "$apid" 2>/dev/null; then
    echo "stopped anvil $apid"
  fi
  rm -f "$anvilpid"
fi

echo "down"
