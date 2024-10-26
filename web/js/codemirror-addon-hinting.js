import CodeMirror from "codemirror"

const WORD = /[a-zA-Z0-9_$:]+/, RANGE = 500

// Combines results from a pre-defined wordlist and using words in the document (anyhint)
CodeMirror.registerHelper("hint", "multihint", (cm, options) => {
  const wordRe = options.word || WORD
  const wordlist = options.wordlist
  const cur = cm.getCursor(), currLine = cm.getLine(cur.line)

  // Don't complete at the middle of words
  if (options.wordEndOnly && wordRe.test(currLine.charAt(cur.ch)))
    return;

  // Find auto-completed word
  let start = cur.ch
  while (start && wordRe.test(currLine.charAt(start - 1))) --start;
  const currWord = start < cur.ch ? currLine.slice(start, cur.ch) : '';

  // Skip short and all-numeric words
  if (options.minSearchLen != null && currWord.length < options.minSearchLen)
    return;
  if (/^\d+$/.test(currWord))
    return;

  const listhints = wordlistHints(wordlist, currWord)
  const anyhints = anywordHints(cm, options, currWord, listhints)
  const hints = [ ...listhints, ...anyhints ]
    .sort(matchSorter(currWord))

  // Don't suggest the word being typed as the only suggestion,
  // unless its a function with a useful displayText that includes the arguments.
  if (hints.length == 1 && hints[0].text == currWord && !hints[0].displayText)
    return;

  if (hints.length > 0 && (!options.displayIfLess || hints.length < options.displayIfLess)) {
    return {
      list: hints,
      from: CodeMirror.Pos(cur.line, start),
      to: cur,
    }
  }
})

// Prefer matches that start with currWord first, then functions over variables, then by name
const matchSorter = currWord => (a, b) => {
  const aStarts = a.text.startsWith(currWord), bStarts = b.text.startsWith(currWord)
      , aIsFunc = !!a.displayText, bIsFunc = !!b.displayText
  return aStarts != bStarts ? (aStarts ? -1 : 1)
       : aIsFunc != bIsFunc ? (aIsFunc ? -1 : 1)
       : a.text < b.text ? -1 : 1
}

// Get hints from the built-in autocomplete list of stdlib variables/functions
function wordlistHints(wordlist, currWord) {
  wordlist._hints = wordlist._hints || [
    ...wordlist.vars.map(([ name, type ]) => ({
      text: name,
      displayText: `${name} · ${type}`
    })),
    ...wordlist.funcs.map(([ name, args ]) => ({
      text: name,
      // args are null for native functions
      displayText: `${name}(${args != null ? args : '..'})`,
      hint: applyFuncHint
    }))
  ]

  // Returns everything when completing an empty string
  return !currWord ? wordlist._hints :
    wordlist._hints.filter(w => w.text.indexOf(currWord) != -1)
}

function applyFuncHint(cm, data, completion) {
    const from = completion.from || data.from, to = completion.to || data.to
    // Add parenthesis and move the cursor into them
    cm.replaceRange(completion.text + '()', from , to, "complete")
    cm.setCursor({ line: to.line, ch: cm.getCursor().ch-1 })
}

// Get hints from words found in the document
// Based on https://codemirror.net/5/addon/hint/anyword-hint.js
function anywordHints(cm, options, currWord, found) {
  if (!currWord) return []

  const wordRe = options.word || WORD
      , range = options.range || RANGE
      , minLen = options.minAnyhintLen
      , maxLen = options.maxAnyhintLen || 40
  const cur = cm.getCursor()
  const re = new RegExp(wordRe.source, "g");
  const matches = new Set, foundWords = new Set(found.map(f => f.text))
  for (let dir = -1; dir <= 1; dir += 2) {
    let line = cur.line, endLine = Math.min(Math.max(line + dir * range, cm.firstLine()), cm.lastLine()) + dir;
    for (; line != endLine; line += dir) {
      let m, text = cm.getLine(line);
      while (m = re.exec(text)) {
        let word = m[0]
        if (line == cur.line && word === currWord) continue;
        word = word.replace(/^:+|:+$/, '')
        if (minLen != null && word.length < minLen) continue;
        if (word.length > maxLen) continue;
        if (foundWords.has(word)) continue;
        if (!/[a-zA-Z$]/.test(word) || /^0x[a-f0-9]+$/.test(word)) continue;
        if (!currWord || word.lastIndexOf(currWord, 0) == 0) {
          matches.add(word);
        }
      }
    }
  }
  return Array.from(matches).map(word => ({ text: word }))
}