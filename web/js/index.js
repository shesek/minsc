import CodeMirror from 'codemirror'
import 'codemirror/addon/mode/simple'
import 'codemirror/addon/edit/matchbrackets'
//import 'codemirror/addon/comment/comment'
//import 'codemirror/addon/comment/continuecomment'
import 'codemirror/addon/selection/active-line'
import 'codemirror/addon/display/fullscreen'
import 'codemirror/addon/search/match-highlighter'
import 'codemirror/addon/hint/show-hint'
import 'codemirror/addon/hint/anyword-hint'
import 'codemirror/addon/runmode/runmode'

import './codemirror-minsc'
import './codemirror-miniscript'
import './codemirror-bitcoin'

import { debounce, encode, findErrorLines, loadGist } from './util'
import default_code from '../default-code.minsc'

const worker = new Worker('./worker.js', { name: 'w', type: 'module' })

const error_el = document.querySelector('#error')
    , head_el = document.querySelector('#live-head')
    , outputs_el = document.querySelector('#outputs')
    , loading_el = document.querySelector('#loading')
    , share_el = document.querySelector('#share')
    , output_el_policy = document.querySelector('#output-policy')
    , output_el_desc = document.querySelector('#output-desc')
    , output_el_script = document.querySelector('#output-script')
    , output_el_other = document.querySelector('#output-other')
    , output_el_address = document.querySelector('#output-address')

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
    error_el.innerText = data.error
    error_el.style.display = 'block'
    markError(data.input, data.error)
  } else if (data.result) {
    const r = data.result
    //console.log(r)
    error_el.style.display = 'none'
    outputs_el.style.display = 'block'

    output_el_policy.style.display = r.policy ? 'block' : 'none'
    output_el_desc.style.display = r.descriptor ? 'block' : 'none'
    output_el_script.style.display = r.script_asm != null ? 'block' : 'none'
    output_el_address.style.display = r.address ? 'block' : 'none'
    output_el_other.style.display = r.other ? 'block' : 'none'

    // If nothing visible is collapsed, collapse the first visible output
    if (!document.querySelector("#outputs > .collapsed[style*=block]")) {
      let visible = document.querySelector("#outputs > [style*=block]")
      if (visible) visible.classList.add('collapsed')
    }

    output_policy.setValue(r.policy || '')
    output_desc.setValue(r.descriptor || '')
    output_script.setValue(r.script_asm || '')
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
function clearErrorMark() {
  if (error_marker) {
    error_marker.clear()
    error_marker = null
  }
}
function markError(code, error) {
  const pos = findErrorLines(code, error)
  if (pos) {
    error_marker = editor.getDoc()
      .markText(pos.from, pos.to, { css: 'color: #8a1f11; background: #FBC2C4' })
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

// Setup main editor
const editor = CodeMirror(document.querySelector('#editor'), {
  mode: 'minsc',
  theme: 'darcula',
  lineNumbers: true,
  lineWrapping: true,
  matchBrackets: true,
  styleActiveLine: true,
  hintOptions: { word: /[\w$:]+/, completeSingle: false },
  highlightSelectionMatches: true, // {showToken: /[\w$:]/},
  // continueComments: true // could not get this to work. :<
  extraKeys: {
    "F11": cm => cm.setOption("fullScreen", !cm.getOption("fullScreen")),
    "Esc": cm => cm.getOption("fullScreen") && cm.setOption("fullScreen", false),
    "Ctrl-Space":  cm => cm.showHint({hint: CodeMirror.hint.anyword }),
  },
  value: initial_code,
})

editor.on('change', debounce((_, c) =>
  c.origin != 'setValue' && update('edit')
, 150))
update('init')

// Setup the 4 output editors (read only)
const output_policy = CodeMirror(output_el_policy.querySelector('.codeview'), {
  mode: 'miniscript',
  readOnly: true,
  lineWrapping: true,
  matchBrackets: true,
  theme: 'darcula',
})
const output_desc = CodeMirror(output_el_desc.querySelector('.codeview'), {
  mode: 'miniscript',
  readOnly: true,
  lineWrapping: true,
  matchBrackets: true,
  theme: 'darcula',
})
const output_script = CodeMirror(output_el_script.querySelector('.codeview'), {
  mode: 'minsc',
  readOnly: true,
  lineWrapping: true,
  matchBrackets: true,
  theme: 'darcula',
})
const output_other = CodeMirror(output_el_other.querySelector('.codeview'), {
  mode: 'minsc',
  readOnly: true,
  lineWrapping: true,
  matchBrackets: true,
  theme: 'darcula',
})
