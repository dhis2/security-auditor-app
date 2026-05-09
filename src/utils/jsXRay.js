// Lazy-loaded wrapper around the js-x-ray analyzer. Importing js-x-ray adds
// ~250 KB to the bundle, so we only pull it in when the Apps Audit tab is
// actually opened (or a test injects an analyzer).
//
// Returns a function `analyze(source) -> { warnings, isMinified, ... }`.
let analyzerPromise = null

export const getAnalyzer = () => {
    if (!analyzerPromise) {
        analyzerPromise = (async () => {
            // js-x-ray's sec-literal dependency uses Node's Buffer for
            // base64 inspection. Browsers don't have it, so we polyfill
            // before loading the analyzer. Ordering matters — js-x-ray
            // captures the global at module init.
            if (typeof globalThis.Buffer === 'undefined') {
                const { Buffer } = await import('buffer')
                globalThis.Buffer = Buffer
            }

            const mod = await import('js-x-ray')
            const fn = mod.runASTAnalysis || mod.default?.runASTAnalysis
            if (typeof fn !== 'function') {
                throw new Error(
                    'js-x-ray runASTAnalysis not found — module shape may have changed'
                )
            }
            return fn
        })()
    }
    return analyzerPromise
}

// Test seam: install a fake analyzer Promise (so tests don't need to import
// the real package). Resetting passes `null` to clear.
export const __setAnalyzerForTests = (fn) => {
    analyzerPromise = fn ? Promise.resolve(fn) : null
}
