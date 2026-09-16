#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$ROOT" ]; then
  echo "Run inside the repository."
  exit 2
fi
cd "$ROOT"

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <phase-number>"
  echo "Example: $0 01"
  exit 2
fi

phase="$1"
match="$(find codex-prompts -maxdepth 1 -type f -name "${phase}-*.md" | sort | head -n1)"

if [ -z "$match" ]; then
  echo "No prompt found for phase: $phase"
  exit 1
fi

echo "Prompt: $match"
echo
cat "$match"
echo
echo "Start Codex with this prompt using:"
printf 'codex "$(cat %q)"\n' "$match"
