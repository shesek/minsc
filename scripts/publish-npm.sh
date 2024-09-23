#!/bin/bash

rm -r node-pkg
wasm-pack build --target nodejs --out-dir node-pkg . --features wasm
(cd node-pkg && npm publish)
