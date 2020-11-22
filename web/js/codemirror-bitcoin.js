import CodeMirror from 'codemirror'

CodeMirror.defineSimpleMode("bitcoin",{
  start: [

    /*
    {
        token: 'operator',
        regex: /OP_(NOP|IF|NOTIF|ELSE|ENDIF|VERIFY|RETURN)(?!\w)/
    },
    {
        token: 'stack',
        regex: /OP_(TOALTSTACK|FROMALTSTACK|IFDUP|DEPTH|DROP|DUP|NIP|OVER|PICK|ROLL|ROT|SWAP|TUCK|2DROP|2DUP|3DUP|2OVER|2ROT|2SWAP)(?!\w)/
    },
    {
        token: 'splice',
        regex: /OP_(CAT|SUBSTR|LEFT|RIGHT|SIZE)(?!\w)/
    },
    {
        token: 'logic',
        regex: /OP_(INVERT|AND|OR|XOR|EQUALVERIFY|EQUAL)(?!\w)/
    },
    {
        token: 'arithmetic',
        regex: /OP_((\d){0,1}(ADD|SUB|MUL|DIV)(?!\w)|NOT(?!\w)|0NOTEQUAL|(R|L)SHIFT|BOOL(AND|OR)|NUMEQUAL((?!\w)|(\w{6}))|NUMNOTEQUAL|(LESS|GREATER)THAN((?!\w)|OREQUAL)|(NEGATE|ABS|MIN|MAX|WITHIN|MOD))/
    },
    
    {
        token: 'string',
        regex: /OP_(RIPEMD160|SHA(1|256)|HASH(160|256)|CODESEPARATOR|CHECK(MULTI){0,1}SIG(VERIFY){0,1})/
    },
    
    {
        token: 'pseudo',
        regex: /OP_(PUBKEY((?!\w)|(HASH))|INVALIDOPCODE)/
    },
    {
        token: 'reserved',
        regex: /OP_(RESERVED((?!\w)|(1|2))|VER((?!\w)|(NOT){0,1}IF(?!\w))|NOP(\d){1,2})/
    },*/

    {
				token: 'atom',
				regex:/OP_([0-9]{1,2}|FALSE|N(.)A|PUSHDATA(1|2|4){0,1}|1NEGATE|TRUE)(?!\w)/,
		},
    {
        token: 'number',
        regex: /\b\d+\b/,
    },
    {
        token: 'variable-3',
        regex: /<[^>]+>|\b[a-f0-9]+\b/,
    },
    /*{
        token: 'operator',
        regex: /OP_(NOP|IF|NOTIF|ELSE|ENDIF|VERIFY|RETURN)\b/
    },*/
    {
        token: 'builtin',
        regex: /OP_\w+/,
    },

  ],
  meta: {
    fold: "brace"
  }
});


CodeMirror.defineMIME("text/x-bitcoinsrc", "bitcoin");
CodeMirror.defineMIME("text/bitcoin-script", "bitcoin");
