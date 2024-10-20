#!/bin/bash
set -eo pipefail
: ${MINSC_EXE:="cargo run --quiet --"}
: ${EXAMPLES_DIR:="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../examples" && pwd)"}

# Examples don't typically contain assertions, but we can check they don't crash as a sanity check
for example in $EXAMPLES_DIR/*.minsc; do
  echo -e "\e[32m\e[1mRunning example:\e[0m $example" >&2
  $MINSC_EXE $example || { e=$?; echo -e "\n\e[31m\e[1mFailed:\e[0m $example" >&2; exit $e; }
  echo -e "\e[32m✔ $example exited successfully\e[0m\n" >&2
done

echo -e "\e[32m\e[1m✔ All examples exited successfully 👍\e[0m" >&2