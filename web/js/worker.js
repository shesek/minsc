let minsc, pending

import('../pkg/index.js').then(module => {
  minsc = module
  debugger
  if (pending) {
    run(pending)
    pending = null
  }
}).catch(console.error)

addEventListener('message', ({ data: req }) => {
  if (!minsc) {
    pending = req
  } else {
    run(req)
  }
})

function run({ code, desc_type, network, child_code }) {
  try {
    const result = minsc.compile(code, desc_type, network, child_code)
    postMessage({ result })
  } catch (err) {
    console.error(''+err, err.stack)
    postMessage({ error: err.toString(), input: code })
  }
}
