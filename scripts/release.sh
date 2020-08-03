#!/bin/bash
set -xeo pipefail

if ! git diff-index --quiet HEAD; then
  echo git working directory is dirty
  exit 1
fi

version=`cat Cargo.toml | egrep '^version =' | cut -d'"' -f2`

if [[ "$1" == "patch" ]]; then
  # bump the patch version by one
  version=`node -p 'process.argv[1].replace(/\.(\d+)$/, (_, v) => "."+(+v+1))' $version`
  sed -i 's/^version =.*/version = "'$version'"/' Cargo.toml
elif [[ "$1" != "nobump" ]]; then
  echo invalid argument, use "patch" or "nobump"
  exit 1
fi

# Extract unreleased changelog & update version number
changelog="`sed -nr '/^## (Unreleased|'$version' )/{n;:a;n;/^## /q;p;ba}' CHANGELOG.md`"
grep '## Unreleased' CHANGELOG.md > /dev/null \
  && sed -i "s/^## Unreleased/## $version - `date +%Y-%m-%d`/" CHANGELOG.md

echo -e "Releasing Minsc v$version\n\n$changelog\n\n"

echo Running cargo check and fmt...
cargo check
cargo fmt -- --check

if [ -z "$SKIP_GIT" ]; then
  echo Tagging...
  git add Cargo.{toml,lock} CHANGELOG.md
  git commit -S -m v$version
  git tag --sign -m "$changelog" v$version
  git branch -f latest HEAD

  echo Pushing to github...
  git push gh master latest
  git push gh --tags
fi

if [ -z "$SKIP_CRATE" ]; then
  echo Publishing to crates.io...
  cargo publish
fi

if [ -z "$SKIP_NPM" ]; then
  echo Publishing to npm...
  ./scripts/publish-npm.sh
fi
