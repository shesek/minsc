#!/bin/bash

rm -r node-pkg
wasm-pack build --target nodejs --out-dir node-pkg
#(cd node-pkg && npm publish)
