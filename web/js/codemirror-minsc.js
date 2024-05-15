import CodeMirror from 'codemirror'

CodeMirror.defineSimpleMode("minsc",{
  start: [
    // Comments
    {regex: /\/\/.*/, token: "comment"},

    // Time durations
    {regex: /\d+(\.\d+)?\s+(years?|months?|weeks?|days?|hours?|min(?:utes?|s)|seconds?)\b/, token: "number"},

    // BTC amounts
    {regex: /\d+(?:\.\d+)?\s+(?:BTC|mBTC|uBTC|bits?|satoshis?|sats?|msats?)\b/, token: "number"},

    // Block height durations
    {regex: /\d+\s+blocks?\b/, token: "number"},

    // Dates
    {regex: /\d{4}-\d{1,2}-\d{1,2}T(\d{1,2}:\d{1,2}(:\d{1,2})?Z?)?\b/, token: "number"},

    // Xpubs, single keys, bytes & hashes
    {regex: /\b([a-fA-F0-9]{8}|[a-fA-F0-9]{40,70}|0x[a-fA-F0-9]*|[xt]pub[0-9a-zA-Z]{100,120})\b/, token: "number"},

    // Addresses (Bech32 & Base58check)
    {regex: /\b[123][0-9a-zA-Z]{25,34}|((bc|tb|bcrt)1[0-9a-z]{38,59}|(BC|TB|BCRT)1[0-9A-Z]{38,59})\b/, token: "number"},

    // Numbers
    {regex: /\b-?\d+(?:\.\d+)?\b/, token: "number"},

    // Strings
    {regex: /"(?:[^\\]|\\.)*?(?:"|$)/, token: "string"},

    // Function definition
    {regex: /\b(fn)(\s+)([$a-zA-Z_][$a-zA-Z_0-9]*(?:::[a-zA-Z0-9_$]+)*)(\(\[native\]\))/, token: ["keyword", null, "def", "def"]},
    {regex: /\b(fn)(\s+)([$a-zA-Z_][$a-zA-Z_0-9]*(?:::[a-zA-Z0-9_$]+)*)\b/, token: ["keyword", null, "def"]},

    // Keywords
    {regex: /\b(of|return|let|if|then|else|_)\b/, token: "keyword"},
    {regex: /\b(true|false|null|default|int|float|str|bytes|likely)\b/, token: "builtin"},

    // Assignment
    //{regex: /\b([$a-zA-Z_][$a-zA-Z_0-9]*)\s*(=)/, token: ["variable-3", null]},

    // Infix operators
    {regex: /[-+\/*<>!;@]|[=!<>]=|&&|\|\||\|/, token: "operator"},

    // Function calls
    {regex: /([$a-zA-Z_][$a-zA-Z_0-9]*(?:::[a-zA-Z0-9_$]+)*)\s*(\()/, token: ["atom", null], indent: true},

    // Variables
    {regex: /[A-Z$][A-Z0-9_]+\b/, token: "variable-2"}, // different look for all-caps identifiers, typically OP_CODES
    {regex: /[$a-zA-Z_][$a-zA-Z_0-9]*(?:::[a-zA-Z0-9_$]+)*\b/, token: "variable-3"},

    // Numeric array index
    {regex: /\.\d+\b/, token: "property"},

    // Script fragment start
    {regex:/`/, token: "property"},

    // Script markers
    {regex: /\s@([\w_$]*|@)/, token: "property"},
    {regex: /(#)\s*("(?:[^\\]|\\.)*?")/, token: ["property", "comment"]},
    {regex: /#/, token: "property"},

    // Indentation for { [ (
    {regex: /[\{\[\(]/, indent: true},
    {regex: /[\}\]\)]/, dedent: true}
  ],
  meta: {
    lineComment: "//",
    fold: "brace"
  }
});