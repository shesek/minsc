import CodeMirror from 'codemirror'

CodeMirror.defineSimpleMode("minsc",{
  start: [
    // Time durations
    {regex: /\d+(\.\d+)?\s+(years?|months?|weeks?|days?|hours?|min(?:utes?|s)|seconds?)\b/, token: "number"},
    // BTC amounts
    {regex: /(?:BTC|mBTC|uBTC|bits?|satoshis?|sats?|msats?)\b/, token: "builtin"},
    // Block height durations
    {regex: /\d+\s+blocks?\b/, token: "number"},
    // Dates
    {regex: /\d{4}-\d{1,2}-\d{1,2}(\s+\d{1,2}:\d{1,2})?\b/, token: "number"},
    // Xpubs, single keys & hashes
    {regex: /\b([a-fA-F0-9]{8}|[a-fA-F0-9]{40,130}|0x[a-fA-F0-9]*|[xt]pub[0-9a-zA-Z]{100,120})\b/, token: "number"},
    // Numbers
    {regex: /\b-?\d+(?:\.\d+)?\b/, token: "number"},
    // Strings
    {regex: /"(?:[^\\]|\\.)*?(?:"|$)/, token: "string"},

    // Keywords
    {regex: /\b(of|return|let|heightwise|likely|if|then|else|true|false)\b/, token: "keyword"},

    // Function definition
    {regex: /\b(fn)(\s+)([$a-zA-Z0-9_]\w*)/, token: ["keyword", null, "def"]},

    // Assignment
    //{regex: /\b([$a-zA-Z_][$a-zA-Z_0-9]*)\s*(=)/, token: ["variable-3", null]},

    // Comments
    {regex: /\/\/.*/, token: "comment"},

    // Infix operators
    {regex: /[-+\/*<>!;@]|[=!<>]=|&&|\|\|/, token: "operator"},

    // Function calls
    {regex: /([$a-zA-Z_][$a-zA-Z_0-9]*)\s*(\()/, token: ["atom", null]},

    // Variables
    {regex: /[A-Z$][A-Z0-9_]+\b/, token: "variable-2"},
    {regex: /[$a-zA-Z_][$a-zA-Z_0-9]*\b/, token: "variable-3"},

    // Numeric array index
    {regex: /\.\d+\b/, token: "property"},

    // Indentation for { [ (
    {regex: /[\{\[\(]/, indent: true},
    {regex: /[\}\]\)]/, dedent: true}
  ],
  meta: {
    lineComment: "//",
    fold: "brace"
  }
});
