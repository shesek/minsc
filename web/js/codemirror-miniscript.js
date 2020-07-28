import CodeMirror from 'codemirror'

CodeMirror.defineSimpleMode("miniscript",{
  start: [
    {
        token: 'keyword',
        regex: /[a-z]+:/,
    },
    {
        token: 'operator',
        regex: /[,@]/,
    },
    {
        regex: /(and|and_[a-z]+|or|or_[a-z]+|thresh|multi)(\()/,
        token: ['keyword', null]
    },
    {
        token: ['builtin', null],
        regex: /([\w_]+)(\()/,
    },
    {
        token: 'number',
        regex: /\d+/,
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
