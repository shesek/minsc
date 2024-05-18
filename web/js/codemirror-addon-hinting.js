import CodeMirror from "codemirror"

const WORD = /[\w$:]+/, RANGE = 500

// Combines results from a pre-defined wordlist and using words in the document (anyhint)
CodeMirror.registerHelper("hint", "multihint", (cm, options) => {
  const word = options.word || WORD
  const wordlist = options.wordlist
  const cur = cm.getCursor(), currLine = cm.getLine(cur.line)

  // Don't complete at the middle of words
  if (options.wordEndOnly && word.test(currLine.charAt(cur.ch)))
    return;

  // Find auto-completed word
  let start = cur.ch
  while (start && word.test(currLine.charAt(start - 1))) --start;
  const currWord = start < cur.ch ? currLine.slice(start, cur.ch) : '';

  if (options.minSearchLen != null && currWord.length < options.minSearchLen)
    return;

  // Get hints from the built-in autocomplete wordlist
  const listhints = currWord ? wordlist.filter(kw => kw.indexOf(currWord) != -1) : wordlist
  // Get hints from elsewhere in the document
  const anyhints = currWord ? anyword(cm, options, currWord) : []
  const words = new Set([ ...listhints, ...anyhints ])

  // Don't suggest the word being typed as the only suggestion
  if (words.size == 1) words.delete(currWord)

  if (words.size > 0 && (!options.displayIfLess || words.size < options.displayIfLess)) {
    return {
      list: Array.from(words).sort(matchSorter(currWord)),
      from: CodeMirror.Pos(cur.line, start),
      to: cur, // CodeMirror.Pos(cur.line),
    }
  }
})

// Show matches that start with currWord first, then by name
const matchSorter = currWord => (a, b) => {
  const aStarts = a.startsWith(currWord), bStarts = b.startsWith(currWord)
  return aStarts != bStarts ? (aStarts ? -1 : 1)
    : a < b ? -1 : 1
}


// Based on https://codemirror.net/5/addon/hint/anyword-hint.js
function anyword(cm, options, currWord) {
  const wordRe = options.word || WORD
      , range = options.range || RANGE
      , minLen = options.minAnyhintLen
      , maxLen = options.maxAnyhintLen || 40
  const cur = cm.getCursor()
  const re = new RegExp(wordRe.source, "g");
  const matches = []
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
        if (!/[a-zA-Z$]/.test(word) || /^0x[a-f0-9]+$/.test(word)) continue;
        if (!currWord || word.lastIndexOf(currWord, 0) == 0) {
          matches.push(word);
        }
      }
    }
  }
  return matches
}