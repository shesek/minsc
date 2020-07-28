import Promise from 'es6-promise'
import * as ms from './miniscript'

let minsc, pending, ready

Promise.all([
  import('../pkg').then(module => minsc = module)
, ms.ready
]).then(_ => {
  ready = true
  if (pending) {
    run(pending)
    pending = null
  }
}).catch(console.error)

addEventListener('message', ({ data: code }) => {
  if (!ready) {
    pending = code
  } else {
    run(code)
  }
})

function run(code) {
  try {
    const policy = minsc.compile(code)
    const { miniscript, script, analysis } = ms.compile_policy(policy);
    postMessage({ result: { policy, miniscript, script, analysis } })
  } catch (err) {
    console.error(''+err, err.stack)
    postMessage({ error: err.toString(), input: code })
  }
}
