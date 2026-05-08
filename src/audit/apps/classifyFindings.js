// Map js-x-ray warning kinds to our existing fail/warning/pass status model.
// js-x-ray warning kinds (subset most relevant for malware-like detection):
//
//   obfuscated-code         the file looks packed/obfuscated by a known tool
//   encoded-literal         hex/base64 literal of suspect entropy/length
//   unsafe-import           dynamic require/import of a remote URL
//   unsafe-stmt             direct eval / new Function with code-string args
//   weak-crypto             use of MD5/SHA1
//   short-identifiers       all identifiers reduced to <= 2 chars (minified-or-obfuscated)
//   suspicious-literal      string concatenation building a code-like payload
//   parsing-error           JS-X-Ray's parser failed
//
// We treat the strong indicators as fail, the medium ones as warning, and
// merely-minified or low-confidence ones as informational (no status bump).
const FAIL_KINDS = new Set([
    'obfuscated-code',
    'unsafe-import',
    'unsafe-stmt',
])
const WARNING_KINDS = new Set([
    'encoded-literal',
    'weak-crypto',
    'suspicious-literal',
    'parsing-error',
])
const INFO_KINDS = new Set(['short-identifiers'])

const STATUS_RANK = { pass: 0, info: 0, warning: 1, fail: 2, error: 3 }

const statusForKind = (kind) => {
    if (FAIL_KINDS.has(kind)) return 'fail'
    if (WARNING_KINDS.has(kind)) return 'warning'
    if (INFO_KINDS.has(kind)) return 'info'
    return 'warning' // unknown kinds default to warning, not silent pass
}

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
