#!/bin/bash
set -eo pipefail
wasm-pack build --target nodejs --out-dir "$PWD/../node-pkg" "$PWD/.." --features playground

node -p '
  const [ vars, funcs ] = JSON.parse(require("../node-pkg/minsc.js").playground_eval(`
    [
      env(0) | filter(|$kv| !isFunction($kv.1)) | map(|$kv| $kv.0: typeof($kv.1)),
      env(0) | filter(|$kv| isFunction($kv.1))  | map(|$kv| $kv.0: str($kv.1)),
    ]
  `));
  const excluded = k => /^(_|OP_RETURN_|OP_PUSHBYTES_|OP_PUSHNUM_)|^(main|T)$/.test(k);
  JSON.stringify({
    vars: vars.filter(([k, _]) => !excluded(k)),
    funcs: funcs.filter(([k, _]) => !excluded(k)).map(([ k, def ]) => [
      k,
      !def.includes("[native]") ? def.slice(def.indexOf("(")+1, def.length-1) : null
    ]),
  }, null, 2)
' | tee js/stdlib-wordlist.json
