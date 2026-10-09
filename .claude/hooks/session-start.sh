#!/bin/bash
# SessionStart: install/verify the RE toolchain (idempotent; ~80s on a fresh container, ~2s when cached).
# Runs only in Claude Code cloud sessions unless RE_LAB_AUTOSETUP=1 (avoid surprise apt installs on laptops).
set -uo pipefail
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ] && [ "${RE_LAB_AUTOSETUP:-}" != "1" ]; then
  echo "RE lab: not a cloud session; run ./setup.sh manually if tools are missing (re-doctor)."
  exit 0
fi
cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"
mkdir -p /opt/re/logs 2>/dev/null || true
if ./setup.sh > /opt/re/logs/session-start.log 2>&1; then
  echo "RE lab ready (tools on PATH; details: re-doctor). Start with: re-auto <file>"
else
  echo "RE lab setup had failures - see /opt/re/logs/session-start.log; re-run ./setup.sh"
  grep -E "FAIL" /opt/re/logs/session-start.log | head -5
fi
[ -n "${CLAUDE_ENV_FILE:-}" ] && echo "export RE_HOME=/opt/re" >> "$CLAUDE_ENV_FILE"
exit 0
