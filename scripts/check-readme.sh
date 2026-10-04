#!/usr/bin/env bash
# Fails if the README's demo block differs from what the built binary prints.
set -euo pipefail
cd "$(dirname "$0")/.."
bin=${PGWARDEN:-./target/release/pgwarden}
expected=$(awk '/<!-- demo:start -->/{f=1;next} /<!-- demo:end -->/{f=0} f' README.md | sed '1d;$d')
# exit 1 is expected: the fixture has findings at or above the default level
actual=$( ("$bin" scan --brief testdata/vulnerable || test $? -eq 1) | tr -d '\r')
if [ "$expected" != "$actual" ]; then
  diff <(echo "$expected") <(echo "$actual") || true
  echo "README demo is out of date" >&2
  exit 1
fi
echo "README demo matches"
