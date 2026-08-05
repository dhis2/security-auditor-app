// SHA-256 of a fetched file, used to detect that an installed app's code
// changed without its version changing.
//
// Hashes the decoded text rather than the raw response bytes. That is stable
// as long as the same file always decodes the same way (it does — the server
// serves the same bytes with the same charset), and it keeps the fetch seam
// returning plain strings, which is what every caller and test already uses.

// SubtleCrypto is only exposed in a secure context: HTTPS, or localhost. A
// DHIS2 instance served over plain HTTP therefore cannot hash, and that is
// reported rather than silently producing no baseline.
export const hashingAvailable = () =>
    typeof globalThis.crypto?.subtle?.digest === 'function' &&
    typeof globalThis.TextEncoder === 'function'

export const HASH_UNAVAILABLE_REASON =
    'Web Crypto is unavailable — this usually means the instance is served over plain HTTP rather than HTTPS.'

const toHex = (buffer) => {
    const bytes = new Uint8Array(buffer)
    let out = ''
    for (const byte of bytes) {
        out += byte.toString(16).padStart(2, '0')
    }
    return out
}

// Returns a lowercase hex SHA-256, or null when hashing isn't possible.
// Null is a first-class outcome, not an error: the scan still reports
// findings, it just cannot contribute to the integrity baseline.
export const hashSource = async (source) => {
    if (!hashingAvailable() || typeof source !== 'string') {
        return null
    }
    try {
        const bytes = new globalThis.TextEncoder().encode(source)
        return toHex(await globalThis.crypto.subtle.digest('SHA-256', bytes))
    } catch {
        return null
    }
}
