import { INTEGRITY } from './appsBaseline'
import { resolveScanLimits } from './scanLimits'

// Map js-x-ray warning kinds to our fail/warning/info/pass status model.
//
// Calibration note (measured against DHIS2 2.43.1 on play.im.dhis2.org, eight
// production app bundles pulled straight off the server):
//
//   every single bundle          → unsafe-stmt ×3, encoded-literal ×1,
//                                  short-identifiers ×1
//   untouched react-dom prod     → unsafe-assign ×219
//
// All of those originate in shared vendor code, not in DHIS2 app code:
//
//   unsafe-stmt        `Function("return this")()` — the globalThis shim in
//                      lodash and in UMD wrappers. Present in essentially
//                      every bundle ever shipped.
//   encoded-literal    the string "added", an i18next event name. sec-literal
//                      scores short lowercase words as candidate base64.
//   short-identifiers  minification, nothing more.
//
// js-x-ray is designed to analyze *unminified npm package source* at publish
// time. Minification removes the identifier and string structure its
// heuristics depend on, and bundling inlines third-party code whose benign
// idioms are indistinguishable from obfuscation at the token level. On
// minified bundles these kinds are therefore treated as observations, not
// verdicts: they are reported so a human can look, but they do not fail an
// app.
//
// Only `obfuscated-code` still fails. js-x-ray emits it when it positively
// fingerprints a known obfuscator (jsfuck, obfuscator.io, freejsobfuscator,
// …) rather than on a heuristic score — it produced zero hits across all
// eight known-good bundles.
//
// Do not "upgrade" to @nodesecure/js-x-ray (the maintained successor to the
// pinned js-x-ray 3.2.0) expecting fewer false positives here — measured on
// v16.0.0 against the same known-good bundles, it is strictly worse for
// minified app code:
//
//   obfuscated-code ×1   value "trojan-source", i.e. bidirectional Unicode
//                        control characters — which any app bundling RTL
//                        (Arabic/Persian/Urdu) translations legitimately has.
//                        That is the one kind we still fail on, so every app
//                        would go red again.
//   shady-link ×40       22 of them "http://www.w3.org/2000/svg" — the SVG
//                        namespace URI present in every React app.
//   unsafe-import ×23    ordinary code-split chunk loading.
//
// It is also 8-10x slower (≈4.7 s per 640 KB bundle vs ≈0.5 s, and 47 s on
// capture's 6.4 MB chunk) on what is the browser's main thread.
const FAIL_KINDS = new Set(['obfuscated-code'])

// Rare enough in a legitimate bundle to be worth a human's attention, but not
// conclusive on their own. Zero hits across the eight known-good bundles.
const WARNING_KINDS = new Set([
    'unsafe-import', // dynamic require/import of a remote URL
    'suspicious-literal', // concatenation building a code-like payload
    'weak-crypto', // MD5/SHA1
])

// Reported, never escalated. See the calibration note above.
const INFO_KINDS = new Set([
    'unsafe-stmt',
    'encoded-literal',
    'short-identifiers',
    'parsing-error',
])

const STATUS_RANK = { pass: 0, info: 0, warning: 1, fail: 2, error: 3 }

const statusForKind = (kind) => {
    if (FAIL_KINDS.has(kind)) {
        return 'fail'
    }
    if (WARNING_KINDS.has(kind)) {
        return 'warning'
    }
    if (INFO_KINDS.has(kind)) {
        return 'info'
    }
    return 'warning' // unknown kinds default to warning, not silent pass
}

// Benign-pattern suppression lives in its own module so the scan worker can
// use it without pulling in i18n. Re-exported here because this is where
// callers have always found it.
export { suppressBenign } from './suppressBenign'

// --- status reduction ------------------------------------------------------

// Reduce a list of warnings to a single per-file status.
export const fileStatus = (warnings) => {
    let best = 'pass'
    for (const w of warnings || []) {
        const s = statusForKind(w.kind)
        if (STATUS_RANK[s] > STATUS_RANK[best]) {
            best = s
        }
    }
    return best
}

// Known-vulnerable libraries are a different class of finding from the AST
// heuristics above: the claim is "this bundle contains lodash 4.17.21, which
// is affected by CVE-2021-23337", which is checkable against a published
// advisory rather than inferred from what the code looks like. So unlike the
// heuristics, these do set a verdict.
//
// Severity comes from Retire.js, which takes it from the advisory. The
// mapping is deliberately one step gentler than the raw severity: a
// vulnerable library in a bundle is not automatically an exploitable path in
// this app, and an admin cannot patch a bundled dependency themselves — the
// action is to report it upstream or upgrade DHIS2.
const SEVERITY_STATUS = {
    critical: 'fail',
    high: 'fail',
    medium: 'warning',
    low: 'info',
}

export const libraryStatus = (libraries) => {
    let best = 'pass'
    for (const library of libraries || []) {
        for (const vuln of library.vulnerabilities || []) {
            const s = SEVERITY_STATUS[vuln.severity] || 'warning'
            if (STATUS_RANK[s] > STATUS_RANK[best]) {
                best = s
            }
        }
    }
    return best
}

// Every vulnerable library found across an app's files, de-duplicated by
// component and version — the same library appears in several chunks.
export const vulnerableLibraries = (files) => {
    const byKey = new Map()
    for (const file of files || []) {
        for (const library of file.libraries || []) {
            if (!library.vulnerabilities?.length) {
                continue
            }
            const key = `${library.component}@${library.version}`
            if (!byKey.has(key)) {
                byKey.set(key, { ...library, files: [] })
            }
            byKey.get(key).files.push(file.src)
        }
    }
    return [...byKey.values()]
}

// Reduce a whole scanApp result to a status. Distinct from appStatus because
// an app can fail or go unscanned before any file is read — previously those
// results reached appStatus([]) and were reported as `pass`, so an app whose
// index.html could not be fetched looked clean.
//
// Integrity drift outranks everything the analyzer can say. "This app's code
// changed while its version stayed the same" is a fact about the server, not
// a heuristic about the code, and it is the one finding here with no benign
// explanation on a machine nobody has been editing by hand.
export const resultStatus = (result) => {
    if (!result) {
        return 'error'
    }
    if (result.integrity?.state === INTEGRITY.DRIFT) {
        return 'fail'
    }
    if (result.error) {
        return 'error'
    }
    if (result.notScanned) {
        return 'info'
    }
    return appStatus(result.files)
}

// Reduce per-file results to a per-app status.
export const appStatus = (fileResults) => {
    let best = 'pass'
    for (const fr of fileResults || []) {
        // A file the analyzer could not read can still yield a library
        // finding, so both contribute regardless of the analyzer's outcome.
        for (const s of [
            fr.error ? 'error' : fileStatus(fr.warnings),
            libraryStatus(fr.libraries),
        ]) {
            if (STATUS_RANK[s] > STATUS_RANK[best]) {
                best = s
            }
        }
    }
    return best
}
