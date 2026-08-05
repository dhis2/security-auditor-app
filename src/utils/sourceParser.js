// Lazy accessor for the JavaScript parser used by the endpoint analysis.
//
// Loaded on demand so a ~140 KB parser does not sit in the app bundle for a
// scan that may never be run — the same treatment js-x-ray gets. The worker
// imports meriyah statically instead, because the platform builds workers in
// `iife` format and Vite cannot code-split those.
let parserPromise = null

export const getSourceParser = () => {
    if (!parserPromise) {
        parserPromise = (async () => {
            const { parseModule, parseScript } = await import('meriyah')
            // Modules first — app bundles are ESM — then a script retry for
            // the vendored files that are not.
            return (source) => {
                try {
                    return parseModule(source, { next: true })
                } catch {
                    return parseScript(source, { next: true })
                }
            }
        })()
    }
    return parserPromise
}

// Test seam, mirroring __setAnalyzerForTests.
export const __setSourceParserForTests = (parse) => {
    parserPromise = parse ? Promise.resolve(parse) : null
}
