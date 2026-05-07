// Single shared fetch for /api/me response headers. Three call sites (the
// audit runner, the SystemInfo panel, and the report exporter) all need the
// `server` header — without this helper, each does its own fetch.
//
// The Promise is memoized so concurrent callers await the same network roundtrip.
// On failure the cache is cleared so a later caller can retry.

let headersPromise = null

const buildApiMeUrl = (contextPath) =>
    contextPath ? `${contextPath}/api/me` : '../api/me'

export const fetchApiMeHeaders = (contextPath) => {
    if (headersPromise) {
        return headersPromise
    }
    const url = buildApiMeUrl(contextPath)
    headersPromise = fetch(url, { method: 'GET', credentials: 'include' })
        .then((response) => response.headers)
        .catch((err) => {
            headersPromise = null
            throw err
        })
    return headersPromise
}

// Convenience: read the `server` response header. Returns null on any error
// so callers can render a "not available" placeholder without try/catch.
export const getServerHeader = async (contextPath) => {
    try {
        const headers = await fetchApiMeHeaders(contextPath)
        return headers.get('server')
    } catch {
        return null
    }
}

// Test seam — clears the memoized Promise. Not used in production code.
export const __resetApiMeCache = () => {
    headersPromise = null
}
