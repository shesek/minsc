import CodeMirror from 'codemirror'

CodeMirror.defineSimpleMode("minsc",{
  start: [
    {regex: /\d+(\.\d+)?\s+(years?|months?|weeks?|days?|hours?|min(?:ute)?s?|sec(ond)?s?)\b/, token: "number"},
    {regex: /\d+\s+blocks?\b/, token: "number"},
    {regex: /\d{4}-\d{1,2}-\d{1,2}(\s+\d{1,2}:\d{1,2})?\b/, token: "number"},
    {regex: /\b([a-f0-9]{8}|[a-f0-9]{40,130}|[xt]pub[0-9a-zA-Z]{100,120})\b/, token: "number"},
    {regex: /\b\d+\b/, token: "number"},
    {regex: /\b(fn)(\s+)([$a-zA-Z_]\w*)/, token: ["keyword", null, "def"]},
    {regex: /\b(of|return|let|heightwise|likely)\b/, token: "keyword"},
    {regex: /\/\/.*/, token: "comment"},
    {regex: /[-+\/*=<>!;@]+|&&|\|\|/, token: "operator"}, // */
    {regex: /\b(or|and|thresh)\b/, token: "builtin"},
    {regex: /\b(pk|older|after|(sha|hash)256|(ripemd|hash)160|any|all|prob|wsh|wpkh|sh|miniscript|address|script_pubkey|script_witness)\b/, token: "builtin"},
    {regex: /([$a-zA-Z_][$a-zA-Z_0-9]*)\s*(\()/, token: ["atom", null]},
    {regex: /[$a-zA-Z_][$a-zA-Z_0-9]*\b/, token: "variable-3"},
    {regex: /\.\d+\b/, token: "property"},
    {regex: /[\{\[\(]/, indent: true},
    {regex: /[\}\]\)]/, dedent: true}
  ],
  meta: {
    lineComment: "//",
    fold: "brace"
  }
});
