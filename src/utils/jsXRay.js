// Lazy-loaded wrapper around the js-x-ray analyzer. Importing js-x-ray adds
// ~250 KB to the bundle, so we only pull it in when the Apps Audit tab is
// actually opened (or a test injects an analyzer).
//
// Returns a function `analyze(source) -> { warnings, isMinified, ... }`.
let analyzerPromise = null

export const getAnalyzer = () => {
    if (!analyzerPromise) {
        analyzerPromise = import('js-x-ray').then((mod) => {
            // js-x-ray's analyzer entry point. Newer versions expose
            // `runASTAnalysis`; if the API ever changes we surface a clear
            // error rather than failing silently inside the runner.
            const fn = mod.runASTAnalysis || mod.default?.runASTAnalysis
            if (typeof fn !== 'function') {
                throw new Error(
                    'js-x-ray runASTAnalysis not found — module shape may have changed'
                )
            }
            return fn
        })
    }
    return analyzerPromise
}

// Test seam: install a fake analyzer Promise (so tests don't need to import
// the real package). Resetting passes `null` to clear.
export const __setAnalyzerForTests = (fn) => {
    analyzerPromise = fn ? Promise.resolve(fn) : null
}
