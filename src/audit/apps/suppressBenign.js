import { resolveScanLimits } from './scanLimits'

// Suppression of findings we can positively attribute to vendor boilerplate.
//
// Deliberately free of any i18n dependency: this runs inside the scan worker,
// and pulling @dhis2/d2-i18n in would drag browser-oriented code somewhere
// there is no document, as well as forcing the worker bundle to code-split —
// which Vite cannot do for the iife format the platform builds workers with.

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

