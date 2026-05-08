// Single shared fetch for /api/me response headers. Three call sites (the
// audit runner, the SystemInfo panel, and the report exporter) all need the
// `server` header — without this helper, each does its own fetch.
//
// The Promise is memoized per resolved URL so concurrent callers for the same
// instance share one network roundtrip. Keying by URL (not just "is something
// cached?") protects against the rare but real case where the same session
// observes two different `contextPath` values.
// On failure the entry for that URL is cleared so a later caller can retry.

const headerPromisesByUrl = new Map()

const buildApiMeUrl = (contextPath) =>
    contextPath ? `${contextPath}/api/me` : '../api/me'

export const fetchApiMeHeaders = (contextPath) => {
    const url = buildApiMeUrl(contextPath)
    const cached = headerPromisesByUrl.get(url)
    if (cached) {
        return cached
    }
    const promise = fetch(url, { method: 'GET', credentials: 'include' })
        .then((response) => response.headers)
        .catch((err) => {
            headerPromisesByUrl.delete(url)
            throw err
        })
    headerPromisesByUrl.set(url, promise)
    return promise
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

// Test seam — clears the memoized Promises. Not used in production code.
export const __resetApiMeCache = () => {
    headerPromisesByUrl.clear()
}
