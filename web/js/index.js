import CodeMirror from 'codemirror'
import 'codemirror/addon/mode/simple'
import 'codemirror/addon/edit/matchbrackets'

import 'codemirror/addon/runmode/runmode'

import './codemirror-minsc'
import './codemirror-miniscript'
import './codemirror-bitcoin'

import { debounce, encode, findErrorLines } from './util'
import default_code from './default-code'

const worker = new Worker('./worker.js', { name: 'w', type: 'module' })

const error_el = document.querySelector('#error')
    , head_el = document.querySelector('#live-head')
    , outputs_el = document.querySelector('#outputs')
    , loading_el = document.querySelector('#loading')
    , share_el = document.querySelector('#share')
    , output_el_policy = document.querySelector('#output-policy')
    , output_el_miniscript = document.querySelector('#output-miniscript')
    , output_el_script = document.querySelector('#output-script')
    , output_el_other = document.querySelector('#output-other')
    , output_el_address = document.querySelector('#output-address')

const initial_code = location.hash.startsWith('#c=') && location.hash.length > 3
                     ? decodeURIComponent(location.hash.substr(3))
                     : default_code

worker.addEventListener('message', ({ data }) => {
  loading_el.style.display = 'none'
  clearErrorMark()

  if (data.error) {
    error_el.innerText = snipRegexes(data.error)
    error_el.style.display = 'block'
    markError(data.input, data.error)
  } else if (data.result) {
    const r = data.result
    console.log(r)
    error_el.style.display = 'none'
    outputs_el.style.display = 'block'

    output_el_policy.style.display = r.policy ? 'block' : 'none'
    output_el_miniscript.style.display = r.miniscript || r.descriptor ? 'block' : 'none'
    output_el_script.style.display = r.script_asm ? 'block' : 'none'
    output_el_address.style.display = r.address ? 'block' : 'none'
    output_el_other.style.display = r.other ? 'block' : 'none'

    output_policy.setValue(r.policy || '')
    output_miniscript.setValue(r.descriptor || r.miniscript || '')
    output_script.setValue(r.script_asm || '')
    output_other.setValue(r.other || '')
    output_el_address.querySelector('span').innerText = r.address || ''
  }
})

function update(source) {
  clearErrorMark()

  const code = editor.getValue()
      , network = 'testnet'

  const share_uri = `#c=${encode(code)}`
  share_el.href = share_uri
  share_box.value = share_el.href
  if (source != 'init') location.hash = share_uri

  if (code) worker.postMessage({ code, network })
  else error_el.style.display = 'none'

  if (source != 'init') evt[source]()
}

const evt = source => _ => {
  _paq.push(['setCustomUrl', location.href])
  _paq.push(['trackEvent', 'compile', source, ''])
}
evt.try = evt('try')
evt.edit = debounce(evt('edit'), 5000)

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

// Strip expected regexes from error messages, they cause long and ugly errors
const snipRegexes = msg => msg.replace(/((,| or) r#"[^"]+"#)+/g, ', <regexes>')

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
    output_miniscript.refresh()
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
  lineNumbers: true,
  lineWrapping: true,
  matchBrackets: true,
  theme: 'darcula',
  value: initial_code,
})

editor.on('change', debounce((_, c) =>
  c.origin != 'setValue' && update('edit')
, 200))
update('init')

// Setup the 3 compile output editors (read only)
const output_policy = CodeMirror(output_el_policy.querySelector('.codeview'), {
  mode: 'miniscript',
  readOnly: true,
  lineWrapping: true,
  matchBrackets: true,
  theme: 'darcula',
})
const output_miniscript = CodeMirror(output_el_miniscript.querySelector('.codeview'), {
  mode: 'miniscript',
  readOnly: true,
  lineWrapping: true,
  matchBrackets: true,
  theme: 'darcula',
})
const output_script = CodeMirror(output_el_script.querySelector('.codeview'), {
  mode: 'bitcoin',
  readOnly: true,
  lineWrapping: true,
  matchBrackets: true,
  theme: 'darcula',
})
const output_other = CodeMirror(output_el_other.querySelector('.codeview'), {
  mode: 'miniscript',
  readOnly: true,
  lineWrapping: true,
  matchBrackets: true,
  theme: 'darcula',
})
