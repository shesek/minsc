#!/bin/bash

wasm-pack build --target nodejs --out-dir $PWD/../node-pkg

node -p '
  const [ vars, funcs ] = JSON.parse(require("../node-pkg/minsc.js").run(`
    [
      env(0) | filter(|$kv| !isFunction($kv.1)) | map(|$kv| $kv.0),
      env(0) | filter(|$kv| isFunction($kv.1)) | map(|$kv| $kv.0 + " " + str($kv.1)),
    ]
  `));
  JSON.stringify({
    vars: vars.filter(v => v.length >= 2 && !v.startsWith("_")),
    funcs: funcs.filter(v => !v.startsWith("_")).map(def => [
        def.slice(0, def.indexOf(" ")),
        def.slice(def.indexOf("(")+1, def.length-1)
    ]),
  }, null, 2)
' > js/stdlib-wordlist.json
