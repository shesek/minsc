let minsc, pending

import('../pkg/index.js').then(module => {
  minsc = module
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

function run({ code, network }) {
  try {
    const result = minsc.compile(code, network)
    postMessage({ result })
  } catch (err) {
    console.error(''+err, err.stack)
    postMessage({ error: err.toString(), input: code })
  }
}
