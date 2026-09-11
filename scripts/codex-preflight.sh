#!/usr/bin/env bash
set -uo pipefail

echo "== orgscan Codex preflight =="
echo

if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "[FAIL] Run this script from inside the orgscan git repository."
  exit 2
fi

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

echo "[repo] $ROOT"
echo "[branch] $(git branch --show-current 2>/dev/null || true)"
echo

echo "== git status =="
git status --short
echo

echo "== Python =="
python3 --version || true
echo

if [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi

echo "== package/test environment =="
"$PY" - <<'PY'
import sys
print("executable:", sys.executable)
try:
    import orgscan
    print("orgscan import: OK", getattr(orgscan, "__file__", ""))
except Exception as exc:
    print("orgscan import: FAIL:", exc)
PY
echo

echo "== dependency/bootstrap verification =="
if [ -f scripts/bootstrap.py ]; then
  "$PY" scripts/bootstrap.py --verify-only || true
else
  echo "[INFO] scripts/bootstrap.py not found"
fi
echo

echo "== tests =="
if "$PY" -m pytest --version >/dev/null 2>&1; then
  "$PY" -m pytest
  rc=$?
else
  echo "[WARN] pytest is not available in the selected Python environment."
  rc=3
fi

echo
if [ "$rc" -eq 0 ]; then
  echo "[PASS] Baseline tests passed."
else
  echo "[WARN] Baseline tests did not pass (exit $rc). Record failures before modifying code."
fi

exit "$rc"
