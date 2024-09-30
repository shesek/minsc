import CodeMirror from 'codemirror'

let minsc_rules // rules shared for code and output modes

// Mode for Minsc code
CodeMirror.defineSimpleMode("minsc", minsc_rules = {
  start: [
    // Comments
    {regex: /\/\/.*/, token: "comment"},
    {regex: /\/\*\*/, token: "comment", next: "comment"},

    // @ Execution probability operator
    // Matched early to tell apart from @ used as markers inside script fragments
    // (and also has to match prior to numbers and variables)
    {regex: /(\d+)\s*(@)/, token: ["number", "operator"]},
    {regex: /(likely)\s*(@)/, token: ["builtin", "operator"]},
    {regex: /([$a-zA-Z_][$a-zA-Z_0-9:]*)\s*(@)/, token: ["variable-3", "operator"]},

    // Time durations
    {regex: /\d+(\.\d+)?\s+(years?|months?|weeks?|days?|hours?|min(?:utes?|s)|seconds?)\b/, token: "number"},

    // BTC amounts
    {regex: /\d+(?:\.\d+)?\s+(?:BTC|mBTC|uBTC|bits?|satoshis?|sats?|msats?)\b/, token: "number"},

    // Block height durations
    {regex: /\d+\s+blocks?\b/, token: "number"},

    // Dates
    {regex: /\d{4}-\d{1,2}-\d{1,2}T(\d{1,2}:\d{1,2}(:\d{1,2})?Z?)?\b/, token: "number"},

    // Xpubs/Xprvs
    {regex: /[xt](?:pub|prv)[0-9a-zA-Z]{100,120}\b(?![_$]|::)/, token: "number"},

    // BIP32 key origin fingerprint
    {regex: /(\[)([a-fA-F0-9]{8})\b/, token: [null,"number"]},

    // Bytes sequences, including keys and hashes in hex
    {regex: /0x[a-fA-F0-9]*\b/, token: "number"}, // with 0x prefix, any length
    {regex: /([a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{66})\b/, token: "number"}, // no 0x prefix, supported lengths only (for Miniscript compatibility)
    {regex: /0z[A-Za-z0-9+/]+={0,2}/, token: "number"}, // 0z prefix for base64 encoded bytes

    // WIF private key
    {regex: /[KLc][1-9A-HJ-NP-Za-km-z]{51}|[59][1-9A-HJ-NP-Za-km-z]{50}\b(?![_$]|::)/, token: "number"},

    // Addresses (Bech32 & Base58check)
    {regex: /(?:[123mn][1-9A-HJ-NP-Za-km-z]{25,34}|(bc|tb|bcrt)1[0-9a-z]{38,59}|(BC|TB|BCRT)1[0-9A-Z]{38,59})\b(?![_$]|::)/, token: "number"},

    // Numbers
    {regex: /\b-?\d+(?:\.\d+)?\b/, token: "number"},

    // Strings
    {regex: /"(?:[^\\]|\\.)*?(?:"|$)/, token: "string"},

    // Function definition
    {regex: /\b(fn)(\s+)([$a-zA-Z_][$a-zA-Z_0-9]*(?:::[a-zA-Z0-9_$]+)*)(\(\[native\]\))/, token: ["keyword", null, "def", "def"]},
    {regex: /\b((?:dyn )?fn)(\s+)([$a-zA-Z_][$a-zA-Z_0-9]*(?:::[a-zA-Z0-9_$]+)*)\b/, token: ["keyword", null, "def"]},

    // Keywords
    {regex: /(of|return|let|if|then|else|dyn(?: fn)?|_)\b/, token: "keyword"},
    {regex: /(true|false|null|default|likely)\b/, token: "builtin"},

    // Assignment
    //{regex: /\b([$a-zA-Z_][$a-zA-Z_0-9]*)\s*(=)/, token: ["variable-3", null]},

    // Function calls
    {regex: /([$a-zA-Z_][$a-zA-Z_0-9]*(?:::[a-zA-Z0-9_$]+)*)\s*(\()/, token: ["atom", null], indent: true},
    {regex: /([$a-zA-Z_][$a-zA-Z_0-9]*(?:::[a-zA-Z0-9_$]+)*)\s*(\[)/, token: ["atom", null], indent: true},

    // PUSH in Script's Debug format
    {regex: /(OP_PUSHBYTES\w*)\s*([a-f0-9]+)\b/, token: ["variable-2", "number"]},

    // BIP32 derivation
    {regex: /(\d+)(h)\b/, token: ["number", "operator"]}, // hardened derivation step with number literal
    {regex: /\*h\b/, token: "operator"}, // hardened wildcard
    {regex: /m\//, token: "operator"},

    // Variables
    {regex: /[A-Z$][A-Z0-9_]+\b/, token: "variable-2"}, // different look for all-caps identifiers, typically OP_CODES
    // IDENT regex explained in grammar.lalrpop
    {regex: /(?:[a-zA-Z][a-zA-Z0-9]{0,24}|(?:[a-zA-Z][a-zA-Z0-9]*)?[_$][a-zA-Z0-9_$]*|[a-zA-Z_$][a-zA-Z0-9_$]*(?:::[a-zA-Z0-9_$]+)+)(?![a-zA-Z0-9$_]|::)/, token: "variable-3" },

    // Numeric array index
    {regex: /\.\d+\b/, token: "property"},

    // Script fragment start/end
    {regex:/`/, token: "property"},

    // Script markers
    {regex: /\s*@@/, token: "property"},
    {regex: /\s*@[\w_$:]*/, token: "property"},
    {regex: /(#)\s*("(?:[^\\]|\\.)*?")/, token: ["property", "comment"]},
    {regex: /#/, token: "property"},

    // Infix operators
    {regex: /[-+\/*<>!;@]|[=!<>]=|&&|\|\||\|/, token: "operator"},

    // Indentation for { [ (
    {regex: /[\{\[\(]/, indent: true},
    {regex: /[\}\]\)]/, dedent: true}
  ],
  comment: [
    {regex: /.*?\*\//, token: "comment", next: "start"},
    {regex: /.*/, token: "comment"}
  ],
  meta: {
    lineComment: "//",
    blockCommentStart: "/**", // yes, two *'s
    blockCommentStart: "*/",
    dontIndentStates: ["comment"],
    fold: "brace"
  }
});

// Mode for displaying Minsc's evaluation result
CodeMirror.defineSimpleMode("minsc-output",{
  start: [
    // Highlight 0x-less hex sequences of any length >5 bytes
    // Not valid as Minsc code and not used to Display Minsc Values, but may appear as Debug output.
    {regex: /(?:[a-f0-9]{2}){5,}\b/, token: "number"},
    // Reuse the rest of minsc_rules, except for multi-line comments
    ...minsc_rules.start.filter(r => r.next != 'comment'),
  ],
  // `meta` and `comment` not needed for output
});
