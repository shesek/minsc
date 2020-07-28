import CodeMirror from 'codemirror'

CodeMirror.defineSimpleMode("minsc",{
  start: [
    {regex: /\d+(\.\d+)?\s+(years?|months?|weeks?|days?|hours?|min(?:ute)?s?|sec(ond)?s?)\b/, token: "number"},
    {regex: /\d+\s+blocks?\b/, token: "number"},
    {regex: /\d{4}-\d{1,2}-\d{1,2}(\s+\d{1,2}:\d{1,2})?/, token: "number"},
    {regex: /(?:(?:[0-9][0-9_]*)(?:(?:[Ee][+-]?[0-9_]+)|\.[0-9_]+(?:[Ee][+-]?[0-9_]+)?)(?:f32|f64)?)|(?:0(?:b[01_]+|(?:o[0-7_]+)|(?:x[0-9a-fA-F_]+))|(?:[0-9][0-9_]*))(?:u8|u16|u32|u64|i8|i16|i32|i64|isize|usize)?/,
     token: "number"},
    {regex: /(let|fn)(\s+)([a-zA-Z_][a-zA-Z0-9_]*)/, token: ["keyword", null, "def"]},
    {regex: /(of|return|let|heightwise|likely)\b/, token: "keyword"},
    {regex: /\/\/.*/, token: "comment"},
    {regex: /[-+\/*=<>!;@]+|&&|\|\|/, token: "operator"}, // */
    {regex: /(or|and|thresh)\b/, token: "builtin"},
    {regex: /(pk|older|after|(sha|hash)256|(ripemd|hash)160|any|all|prob)\b/, token: "builtin"},
    {regex: /([$a-zA-Z_]\w*)\s*(\()/, token: ["atom", null]},
    {regex: /[$a-zA-Z_]\w*/, token: "variable-3"},
    {regex: /\.\d+\b/, token: "property"},
    {regex: /[\{\[\(]/, indent: true},
    {regex: /[\}\]\)]/, dedent: true}
  ],
  meta: {
    lineComment: "//",
    fold: "brace"
  }
});
