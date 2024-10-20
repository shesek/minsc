#!/bin/bash
set -eo pipefail
: ${MINSC_EXE:="cargo run --quiet --"}
: ${TESTS_DIR:="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"}

for test in $TESTS_DIR/*.minsc; do
  echo -e "\e[32m\e[1mRunning test:\e[0m $test" >&2
  $MINSC_EXE $test || { e=$?; echo -e "\n\e[31m\e[1mFailed:\e[0m $test" >&2; exit $e; }
  echo -e "\e[32m✔ $test passed\e[0m\n" >&2
done

echo -e "\e[32m\e[1m✔ All tests passed 👍\e[0m" >&2