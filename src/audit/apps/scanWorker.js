/* eslint-env worker */
// Import order matters: the polyfill must be evaluated before js-x-ray.
import './bufferPolyfill'
import { runASTAnalysis } from 'js-x-ray'
import { processSource } from './fileProcessor'

// The analysis half of the apps audit, running off the main thread.
//
// js-x-ray's parse is synchronous and takes about a second per 640 KB bundle.
// A scan touches 100+ files, so on the main thread the tab freezes in
// second-long blocks for the length of the run — the progress bar cannot even
// repaint. Here, the main thread does nothing but fetch and update state.
//
// Deliberately small: it owns no scan logic of its own, it only runs
// fileProcessor on request. Anything it did differently from the main-thread
// fallback would be a bug that only appears on one of the two paths.
//
// Everything here is imported statically. The platform builds workers in
// `iife` format, which Vite cannot code-split, so a dynamic import of the
// analyzer — as the main thread uses to keep it out of the initial bundle —
// fails the build outright. Nothing is lost: the worker is its own chunk
// already, and it is only fetched when a scan starts.
//
// Protocol, all messages carrying an `id` that is echoed back:
//   → { type: 'init', repository, limits }   ← { type: 'ready' } | { type: 'error' }
//   → { type: 'file', id, src, source, skipAnalysis }
//                                            ← { type: 'result', id, result }
//
// Failures come back as messages rather than as thrown errors, so the client
// can attribute them to the file that caused them.

const analyze = runASTAnalysis

let repository = null
let limits = null

self.onmessage = async (event) => {
    const message = event.data

    if (message?.type === 'init') {
        repository = message.repository
        limits = message.limits
        self.postMessage({ type: 'ready' })
        return
    }

    if (message?.type === 'file') {
        const { id, src, source, skipAnalysis } = message
        try {
            const result = await processSource({
                src,
                source,
                skipAnalysis,
                limits,
                repository,
                analyze,
            })
            self.postMessage({ type: 'result', id, result })
        } catch (err) {
            self.postMessage({
                type: 'result',
                id,
                result: { analyzeError: err.message || String(err) },
            })
        }
    }
}
