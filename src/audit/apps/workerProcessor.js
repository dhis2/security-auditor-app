// Main-thread client for the scan worker.
//
// Returns a processor with the same shape as the in-thread one, so scanApp is
// written once and neither knows nor cares where the work happened. Returns
// null whenever a worker cannot be used — no Worker in this environment, a
// Content-Security-Policy that forbids one, a bundler that did not emit the
// entry — and the caller falls back to running in-thread, which is what the
// audit did before this existed.
//
// One worker, not a pool. The analysis was already serialised: it is
// synchronous, so `maxAppAuditConcurrency` lanes on the main thread never ran
// two parses at once either. Moving it to a single worker therefore costs no
// throughput and buys a responsive UI. A pool would genuinely be faster, but
// each worker loads its own copy of the analyzer and the signature data, so
// that is a separate trade to make deliberately.

// Resolve when the worker reports itself ready, reject if it fails to load.
// No timeout: a module worker that cannot be fetched or parsed fires `error`,
// which is a real signal, where any timeout would be a number invented to
// stand in for one.
const handshake = (worker, repository, limits) =>
    new Promise((resolve, reject) => {
        const onMessage = (event) => {
            if (event.data?.type === 'ready') {
                cleanup()
                resolve(event.data)
            }
        }
        const onError = (event) => {
            cleanup()
            reject(new Error(event.message || 'scan worker failed to start'))
        }
        const cleanup = () => {
            worker.removeEventListener('message', onMessage)
            worker.removeEventListener('error', onError)
        }
        worker.addEventListener('message', onMessage)
        worker.addEventListener('error', onError)
        worker.postMessage({ type: 'init', repository, limits })
    })

export const createWorkerProcessor = async ({ repository, limits }) => {
    if (typeof Worker === 'undefined') {
        return null
    }

    let worker
    try {
        const { spawnScanWorker } = await import('./spawnScanWorker')
        worker = spawnScanWorker()
        await handshake(worker, repository, limits)
    } catch {
        worker?.terminate()
        return null
    }

    let nextId = 0
    const pending = new Map()

    worker.addEventListener('message', (event) => {
        const { type, id, result } = event.data || {}
        if (type !== 'result') {
            return
        }
        const resolve = pending.get(id)
        if (resolve) {
            pending.delete(id)
            resolve(result)
        }
    })

    // A worker that dies mid-run (out of memory on a very large bundle, say)
    // must not leave the audit waiting for ever. Settle everything in flight
    // so those files are reported as analyzer failures and the scan finishes.
    worker.addEventListener('error', (event) => {
        const message = event.message || 'scan worker stopped'
        for (const [id, resolve] of pending) {
            pending.delete(id)
            resolve({ analyzeError: message })
        }
    })

    return {
        process: ({ src, source, skipAnalysis }) =>
            new Promise((resolve) => {
                const id = nextId++
                pending.set(id, resolve)
                worker.postMessage({
                    type: 'file',
                    id,
                    src,
                    source,
                    skipAnalysis,
                })
            }),
        terminate: () => worker.terminate(),
    }
}
