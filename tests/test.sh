#!/bin/bash
set -eo pipefail
[ -z "$MINSC_EXE" ] && cargo build # build non-quietly before 'cargo run'
: ${MINSC_EXE:=cargo run --quiet --}
: ${TESTS_DIR:=$(realpath --relative-to="$PWD" "$(dirname "${BASH_SOURCE[0]}")")}
: ${EXAMPLES_DIR:=$(realpath --relative-to="$PWD" "$TESTS_DIR/../examples")}

# To run both: $ tests/test.sh examples,tests
RUN=${1:-tests}

if [[ $RUN == *"tests"* ]]; then
  for test in $TESTS_DIR/*.minsc; do
    echo -e "\e[32m\e[1mRunning test:\e[0m $test" >&2
    time $MINSC_EXE $test || { e=$?; echo -e "\n\e[31m\e[1mFailed:\e[0m $test" >&2; exit $e; }
    echo -e "\e[32m✔ $test passed\e[0m\n" >&2
  done
  echo -e "\e[32m\e[1m✔ All tests passed 👍\e[0m" >&2
fi

# Examples don't typically have assertions, but we can at least check they don't crash as a sanity check
if [[ $RUN == *"examples"* ]]; then
  for example in $EXAMPLES_DIR/*.minsc; do
    echo -e "\e[32m\e[1mRunning example:\e[0m $example" >&2
    time $MINSC_EXE $example || { e=$?; echo -e "\n\e[31m\e[1mFailed:\e[0m $example" >&2; exit $e; }
    echo -e "\e[32m✔ $example exited successfully\e[0m\n" >&2
  done
  echo -e "\e[32m\e[1m✔ All examples exited successfully 👍\e[0m" >&2
fi