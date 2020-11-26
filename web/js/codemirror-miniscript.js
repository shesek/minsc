import CodeMirror from 'codemirror'

CodeMirror.defineSimpleMode("miniscript",{
  start: [
    {
        regex: /\b([a-z:_]+)(\()/,
        token: ['keyword', null]
    },
    {
        token: 'operator',
        regex: /[,@]/,
    },
    {
        token: ['builtin', null],
        regex: /([\w_]+)(\()/,
    },
    {
        token: 'number',
        regex: /\b\d+\b/,
    },
    {
        token: "number",
        regex: /\b([a-f0-9]{8,}|[xt]pub[0-9a-zA-Z]{100,120})\b/,
    },
    {
        token: 'variable-3',
        regex: /[\w_]+/,
    },
  ],
  meta: {
    fold: "brace"
  }
});
