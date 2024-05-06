import CodeMirror from 'codemirror'

CodeMirror.defineSimpleMode("bitcoin",{
  start: [
    // Numbers and data pushes
    {
        token: [null, 'number', null],
        regex: /(<)([^>]+)(>)/,
    },
    // Opcodes
    {
        token: 'variable-2',
        regex: /OP_\w+/,
    },
  ],
  meta: {
    fold: "brace"
  }
});

CodeMirror.defineMIME("text/x-bitcoinsrc", "bitcoin");
CodeMirror.defineMIME("text/bitcoin-script", "bitcoin");
