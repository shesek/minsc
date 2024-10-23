export const debounce = (fn, time, timer) => (...args) => {
  if (!timer) fn(...args)
  const tailCall = !!timer
  clearTimeout(timer)
  timer = setTimeout(() => {
    timer = null
    tailCall && fn(...args)
  }, time)
}

export const encode = str =>
  encodeURIComponent(str)
    .replace(/[*._-~'!()]/g, escape)

export function findErrorLines (code, errMessage) {
  const m = errMessage.match(/^Parse error:.* at (\d+)(?::(\d+))?/)
  if (!m) return null

  let [ , start_pos, end_pos ] = m.map(Number)
  if (start_pos >= code.length) start_pos = code.length-1
  if (!end_pos) end_pos = start_pos+1
  const LoC = code.split('\n')

  let pos = 0, line = 0, line_start=0;
  for (; pos <= start_pos; line_start=pos, pos+=LoC.shift().length+1, line++);
  const from = { line: line-1, ch: start_pos - line_start };

  for (; pos <= end_pos && LoC.length; line_start=pos, pos += LoC.shift().length+1, line++);
  const to = { line: line-1, ch: end_pos - line_start };

  return { from, to }
}

export function loadFile(hash) {
  if (hash.startsWith('#github=')) return loadRepoFile(hash.slice(8))
  if (hash.startsWith('#gist=')) return loadGist(hash.slice(6))
}

async function loadRepoFile(path) {
  if (/^(examples|tests|src)\//.test(path)) path=`shesek/minsc/master/${path.replace(/\.minsc$/, '')}.minsc`
  else if (/^(master|dev|20\d{4}-\w+)\//.test(path)) path=`shesek/minsc/${path.replace(/\.minsc$/, '')}.minsc`
  else if (path.startsWith('https://github.com/')) path=path.slice(18)

  const parts = path.split('/')
  if (parts[2] == 'blob') parts.splice(2,1) // drop '/blob/' to support github.com web ui urls

  const resp = await fetch(`https://raw.githubusercontent.com/${parts.join('/')}`)
  if (!resp.ok) throw new Error(`Github file ${parts.join('/')} returned ${resp.status}`)
  const code = await resp.text()

  // Strip final `env::pretty()` calls. This is used in example files meant to be run using CLI, but not needed in the playground.
  return code.replace(/\s*\nenv::pretty\(\)\s*$/, '\n')
}

async function loadGist(identifier) {
  const [ gist_id, file_index ] = identifier.split(':')
  const resp = await fetch(`https://api.github.com/gists/${encodeURIComponent(gist_id)}`)
      , body = await resp.json()
  if (!resp.ok) throw new Error(`Gist ${gist_id} not found`)

  const filenames = Object.keys(body.files)
      , file = body.files[filenames[+file_index || 0]]
  if (!file) throw new Error(`Gist file #${file_index} not found`)

  let code = file.content

  // strip off ```hack syntax highlightning
  if (code.startsWith('```hack')) code = code.trim().slice(8, -4)

  return code
}
