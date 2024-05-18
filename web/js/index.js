import CodeMirror from 'codemirror'
import 'codemirror/addon/mode/simple'
import 'codemirror/addon/edit/matchbrackets'
//import 'codemirror/addon/comment/comment'
//import 'codemirror/addon/comment/continuecomment'
import 'codemirror/addon/selection/active-line'
import 'codemirror/addon/display/fullscreen'
import 'codemirror/addon/hint/show-hint'
import 'codemirror/addon/search/search'
import 'codemirror/addon/search/searchcursor'
import 'codemirror/addon/dialog/dialog'
import 'codemirror/addon/runmode/runmode'

import './codemirror-minsc'
import './codemirror-miniscript'
import './codemirror-bitcoin'
import './codemirror-addon-highlighter'
import './codemirror-addon-hinting'

import stdlib_wordlist from './stdlib-wordlist.json'

import { debounce, encode, findErrorLines, loadGist } from './util'
import default_code from '../default-code.minsc'

const worker = new Worker(new URL("./worker.js", import.meta.url));

const error_el = document.querySelector('#error')
    , head_el = document.querySelector('#live-head')
    , outputs_el = document.querySelector('#outputs')
    , loading_el = document.querySelector('#loading')
    , share_el = document.querySelector('#share')
    , output_el_policy = document.querySelector('#output-policy')
    , output_el_desc = document.querySelector('#output-desc')
    , output_el_script = document.querySelector('#output-script')
    , output_el_address = document.querySelector('#output-address')
    , output_el_tapinfo = document.querySelector('#output-tapinfo')
    , output_el_key = document.querySelector('#output-key')
    , output_el_other = document.querySelector('#output-other')

const gist_id = location.hash.startsWith('#gist=') && location.hash.slice(6)
const initial_code = gist_id ? '' // leave the editor empty while the gist is loading
                     : location.hash.startsWith('#c=') && location.hash.length > 3
                     ? decodeURIComponent(location.hash.slice(3))
                     : default_code

// Load code from gist
if (gist_id) {
  loadGist(gist_id).then(code => {
    editor.setValue(code)
    update('gist')
  }).catch(console.error)
}

// Handle evaluation result message from WebWorker
worker.addEventListener('message', ({ data }) => {
  loading_el.style.display = 'none'
  clearErrorMark()

  if (data.error) {
    const errorMsg = handleError(data.input, data.error)
    error_el.innerText = errorMsg
    error_el.style.display = 'block'
  } else if (data.result) {
    const r = data.result
    //console.log(r)
    error_el.style.display = 'none'
    outputs_el.style.display = 'block'

    output_el_policy.style.display = r.policy ? 'block' : 'none'
    output_el_desc.style.display = r.descriptor ? 'block' : 'none'
    output_el_script.style.display = r.script_asm != null ? 'block' : 'none'
    output_el_address.style.display = r.address ? 'block' : 'none'
    output_el_tapinfo.style.display = r.tapinfo ? 'block' : 'none'
    output_el_key.style.display = r.key ? 'block' : 'none'
    output_el_other.style.display = r.other ? 'block' : 'none'

    // If nothing visible is collapsed, collapse the first visible output
    if (!document.querySelector("#outputs > .collapsed[style*=block]")) {
      let visible = document.querySelector("#outputs > [style*=block]")
      if (visible) visible.classList.add('collapsed')
    }

    output_policy.setValue(r.policy || '')
    output_desc.setValue(r.descriptor || '')
    output_script.setValue(r.script_asm || '')
    output_tapinfo.setValue(r.tapinfo|| '')
    output_key.setValue(r.key || '')
    output_other.setValue(r.other || '')
    output_el_address.querySelector('span').innerText = r.address || ''

    if (r.other) {
      // Clear matchingBracket highlights, they show up automatically when the result display
      // is updated to a text beginning with a bracket, even when the editor is not focused.
      output_other.getAllMarks().filter(m => m.className=='CodeMirror-matchingbracket')
        .forEach(m => m.clear())
    }
  }
})

// Send code to WebWorker for evaluation
function update(source) {
  clearErrorMark()

  const code = editor.getValue()
      , network = 'signet'

  const share_uri = `#c=${encode(code)}`
  share_el.href = share_uri
  share_box.value = share_el.href
  if (source != 'init' && source != 'gist') location.hash = share_uri

  if (code) worker.postMessage({ code, network })
  else error_el.style.display = 'none'
}

let error_marker

function handleError(input, error) {
  const pos = findErrorLines(input, error)
  if (pos) {
    error_marker = editor.getDoc()
      .markText(pos.from, pos.to, { css: 'color: #8a1f11; background: #FBC2C4' })
    error = error.replace(/ at (\d+)(?::(\d+))?/, ` at ${pos.from.line+1}:${pos.from.ch+1}`)
  }
  return error
}

function clearErrorMark() {
  if (error_marker) {
    error_marker.clear()
    error_marker = null
  }
}

// Example snippets
document.querySelectorAll('.snippet').forEach(snippet => {
  const code = snippet.querySelector('code').innerText.trim()

  // Enable "Try" buttons
  snippet.querySelector('button').addEventListener('click', _ => {
    editor.setValue(code)
    update('try')
    head_el.scrollIntoView({ behavior: 'smooth' })
    // firefox mobile sometimes misses the correct position
    setTimeout(_ => head_el.scrollIntoView(), 700)
  })

  // Update snippet <code>s with CodeMirror highlighting (non-editable)
  const target = snippet.querySelector('pre')
  target.classList.add('CodeMirror', 'cm-s-darcula')
  CodeMirror.runMode(code, 'minsc', target)
})

// Collapsible cards (for compile output)
document.querySelectorAll('.card.collapsible').forEach(collapsible => {
  collapsible.querySelector('.card-header').addEventListener('click', _ => {
    collapsible.classList.toggle('collapsed')

    output_policy.refresh()
    output_desc.refresh()
    output_script.refresh()
    output_tapinfo.refresh()
    output_key.refresh()
  })
})

// Share button
const share_box = document.querySelector('#share-box')
share_el.addEventListener('click', _ => {
  share_el.classList.toggle('active')
  share_box.classList.toggle('d-none')

  if (share_el.classList.contains('active')) {
    //share_box.value = share_el.href
    share_box.select()
  }
})

// Enabled for the main editor and read-only view
const full_screen_keys = {
  "F11": cm => cm.setOption("fullScreen", !cm.getOption("fullScreen")),
  "Esc": cm => cm.getOption("fullScreen") && cm.setOption("fullScreen", false),
};

// Setup main editor
const editor = CodeMirror(document.querySelector('#editor'), {
  mode: 'minsc',
  theme: 'darcula',
  tabSize: 2,
  lineNumbers: true,
  lineWrapping: true,
  matchBrackets: true,
  styleActiveLine: true,
  hintOptions: {
    hint: CodeMirror.hint.multihint,
    wordlist: stdlib_wordlist,
    word: /[\w$:]+/,
    closeCharacters: /[\s()\[\]{};>,]/,
    minAnyhintLen: 3,
  },
  highlightSelectionMatches: { showToken: /[\w$:]/ },
  // continueComments: true // could not get this to work. :<
  extraKeys: {
    ...full_screen_keys,
    "Ctrl-Space":  cm => cm.showHint({ completeSingle: true }),
  },
  value: initial_code,
})

// Execute on change
editor.on('change', debounce((_, c) =>
  c.origin != 'setValue' && update('edit')
, 150))
update('init')

// Suggest autocomplete hints
editor.on('inputRead', debounce((cm, changes) => {
  if (!cm.state.completionActive)
    cm.showHint({ completeSingle: false, wordEndOnly: true, minSearchLen: 2, displayIfLess: 35 })
}, 250))

// Setup read-only CodeMirror editors to display outputs
const readOnlyCodeview = (element, mode) =>
  CodeMirror(element.querySelector('.codeview'), {
    mode: mode,
    readOnly: true,
    lineWrapping: true,
    matchBrackets: true,
    theme: 'darcula',
    extraKeys: full_screen_keys,
  })

const output_policy = readOnlyCodeview(output_el_policy, 'miniscript')
    , output_desc = readOnlyCodeview(output_el_desc, 'miniscript')
    , output_script = readOnlyCodeview(output_el_script, 'minsc')
    , output_tapinfo = readOnlyCodeview(output_el_tapinfo, 'minsc')
    , output_key = readOnlyCodeview(output_el_key, 'minsc')
    , output_other = readOnlyCodeview(output_el_other, 'minsc')
