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

// --- benign-pattern suppression -------------------------------------------
//
// Kinds that survive as informational still clutter the findings column with
// the same vendor hits on every app. These suppressors remove the specific
// patterns positively identified as vendor boilerplate, while leaving
// anything else of the same kind visible.

// js-x-ray reports warning locations as either [line, column] or
// [[line, col], [line, col]]. Normalize to the first [line, column] pair.
const startOf = (location) => {
    if (!Array.isArray(location)) {
        return null
    }
    const point = Array.isArray(location[0]) ? location[0] : location
    return typeof point[0] === 'number' && typeof point[1] === 'number'
        ? point
        : null
}

// `Function("return this")` / `Function('return this')` — the standard
// globalThis fallback. Verified to sit exactly at the reported column in
// every DHIS2 bundle checked.
const GLOBAL_THIS_SHIM = /^Function\s*\(\s*(["'])return this\1\s*\)/

const isGlobalThisShim = (warning, lines) => {
    const point = startOf(warning.location)
    if (!point) {
        return false
    }
    const [line, column] = point
    return GLOBAL_THIS_SHIM.test((lines[line - 1] || '').slice(column))
}

// sec-literal scores short identifier-ish strings as candidate base64/hex.
// Observed on live DHIS2 bundles: the i18next event name "added", and DHIS2's
// own error codes ("E1001", "E7113", …) — eleven of them in one chunk. The
// cutoff is a configurable limit, not a constant here; see scanLimits.js for
// the default and its justification.
const isTrivialLiteral = (value, minLength) =>
    typeof value === 'string' && value.length < minLength

// Drop warnings positively attributable to known-benign vendor code.
//
// `source` is the file the warnings came from; without it, nothing that needs
// a location lookup is suppressed. `limits` supplies
// minEncodedLiteralLength — omitted, it falls back to the documented default
// via resolveScanLimits.
export const suppressBenign = (warnings, source, limits) => {
    if (!warnings || warnings.length === 0) {
        return warnings || []
    }
    const { minEncodedLiteralLength } = limits || resolveScanLimits()
    const lines = typeof source === 'string' ? source.split('\n') : null
    return warnings.filter((w) => {
        if (w.kind === 'unsafe-stmt' && lines && isGlobalThisShim(w, lines)) {
            return false
        }
        if (
            w.kind === 'encoded-literal' &&
            isTrivialLiteral(w.value, minEncodedLiteralLength)
        ) {
            return false
        }
        return true
    })
}

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

// Reduce a whole scanApp result to a status. Distinct from appStatus because
// an app can fail or go unscanned before any file is read — previously those
// results reached appStatus([]) and were reported as `pass`, so an app whose
// index.html could not be fetched looked clean.
export const resultStatus = (result) => {
    if (!result) {
        return 'error'
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
        const s = fr.error ? 'error' : fileStatus(fr.warnings)
        if (STATUS_RANK[s] > STATUS_RANK[best]) {
            best = s
        }
    }
    return best
}
