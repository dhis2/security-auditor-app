// Decode base64 and hex string literals, so a URL hidden inside one is read
// rather than merely noted as "a long encoded-looking string".
//
// This is the check that earns its place against deliberately hidden code.
// `fetch(atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYw=="))` defeats every text scan in
// this file; decoding it does not.
//
// Measured on three DHIS2 2.43.1 bundles — 914, 60 and 34 encoded-looking
// candidates respectively — exactly zero decoded to anything containing a URL.
// That silence is the point: a check that never fires on legitimate code means
// something when it fires.
//
// Two guards keep it that way. A decode must produce printable text, which
// rejects the overwhelming majority of base64-shaped strings that are really
// binary, hashes or identifiers; and the result must contain a URL, which is
// the only thing we are looking for.

// Long enough that a decode is plausibly a payload rather than a coincidence.
// Base64 encodes 3 bytes as 4 characters, so 20 characters is ~15 bytes —
// shorter than the shortest URL worth hiding.
const MIN_ENCODED_LENGTH = 20

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/
const HEX = /^(?:[0-9a-fA-F]{2})+$/
const PRINTABLE = /^[\x20-\x7e\s]+$/
const CONTAINS_URL = /\bhttps?:\/\/[a-z0-9.-]+\.[a-z]{2,}/i

const decodeBase64 = (value) => {
    if (typeof globalThis.atob === 'function') {
        return globalThis.atob(value)
    }
    // Node (tests, and the build-time tooling) has no atob.
    return globalThis.Buffer
        ? globalThis.Buffer.from(value, 'base64').toString('binary')
        : null
}

const decodeHex = (value) => {
    let out = ''
    for (let i = 0; i < value.length; i += 2) {
        out += String.fromCharCode(parseInt(value.slice(i, i + 2), 16))
    }
    return out
}

// Decode one string if it is encoded and hides a URL. Returns the decoded text
// or null — null being by far the common case, and cheap to reach.
export const decodeIfHidingUrl = (value) => {
    if (
        typeof value !== 'string' ||
        value.length < MIN_ENCODED_LENGTH ||
        CONTAINS_URL.test(value)
    ) {
        // A plain URL is not hidden; the ordinary scan already has it.
        return null
    }
    // Both encodings are tried rather than chosen by shape. Hex digits are a
    // subset of the base64 alphabet, so a hex payload also matches the base64
    // pattern; picking one on appearance decoded it as the wrong thing and
    // silently missed it.
    for (const [pattern, decode] of [
        [HEX, decodeHex],
        [BASE64, decodeBase64],
    ]) {
        if (!pattern.test(value)) {
            continue
        }
        let decoded
        try {
            decoded = decode(value)
        } catch {
            continue
        }
        if (decoded && PRINTABLE.test(decoded) && CONTAINS_URL.test(decoded)) {
            return decoded
        }
    }
    return null
}

// Candidate encoded strings in a file, for the path where no AST is available.
// Quoted so that a bare run of hex in minified code is not considered.
const QUOTED = /["'`]([A-Za-z0-9+/=]{20,}|(?:[0-9a-fA-F]{2}){10,})["'`]/g

// Every decoded payload found in a source, as { decoded, index }.
export const findDecodedUrls = (source, literals) => {
    const out = []
    if (Array.isArray(literals)) {
        for (const literal of literals) {
            const decoded = decodeIfHidingUrl(literal.value)
            if (decoded) {
                out.push({ decoded, index: literal.index })
            }
        }
        return out
    }
    if (typeof source !== 'string') {
        return out
    }
    QUOTED.lastIndex = 0
    let match
    while ((match = QUOTED.exec(source)) !== null) {
        const decoded = decodeIfHidingUrl(match[1])
        if (decoded) {
            out.push({ decoded, index: match.index })
        }
    }
    return out
}
