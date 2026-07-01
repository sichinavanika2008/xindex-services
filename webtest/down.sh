#!/usr/bin/env bash
# Tear down the web testbed: keeper, dApp server, daemon fleet, anvil.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
out="${WEBTEST_DIR:-/tmp/xindex-webtest}"

for name in keeper http anvil; do
  pid_file="$out/$name.pid"
  [ -f "$pid_file" ] || continue
  pid="$(cat "$pid_file")"
  kill "$pid" 2>/dev/null && echo "stopped $name ($pid)" || true
  rm -f "$pid_file"
done

# Daemon fleet (started by rehearsal/up.sh).
"$repo/rehearsal/down.sh" 2>/dev/null || true

echo "web testbed stopped."
