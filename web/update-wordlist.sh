#!/bin/bash

#wasm-pack build --target nodejs --out-dir $PWD/../node-pkg

node -p '
  const ignored = [ "true", "false", "null" ]
  const words = require("../node-pkg/minsc.js")
    .run("map(env(0), |$kv| $kv.0)");
  JSON.stringify(JSON.parse(words)
    .filter(w => w.length >= 2 && !w.startsWith("_") && !ignored.includes(w)))
' > js/stdlib-wordlist.json
