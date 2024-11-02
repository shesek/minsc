let minsc, pending

import('../pkg/index.js').then(module => {
  minsc = module
  if (pending) run(pending)
}).catch(console.error)

addEventListener('message', ({ data: req }) => {
  // Wait for the next event loop 'tick' before processing, so that we first read all queued messages
  // (multiple could've been accumulated while we were `run()`ing) and only process the latest one
  if (minsc && !pending) setTimeout(() => run(pending), 0)
  pending = req
})

function run({ code, network }) {
  pending = null
  try {
    const result = minsc.run_playground(code, network)
    postMessage({ result })
  } catch (err) {
    console.error(''+err, err.stack)
    postMessage({ error: err.toString(), input: code })
  }
}
