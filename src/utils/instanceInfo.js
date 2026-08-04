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

const buildApiMeFieldsUrl = (contextPath) =>
    `${buildApiMeUrl(contextPath)}?fields=username`

const basicAuth = (username, password) => {
    if (typeof btoa !== 'function') {
        throw new Error('Basic authentication check is not supported in this browser')
    }
    return `Basic ${btoa(`${username}:${password}`)}`
}

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

// Actively test whether the public default DHIS2 admin credentials still work.
// This deliberately omits the current session cookie so it does not replace or
// disturb the logged-in user's browser session.
export const checkDefaultAdminCredentials = async (contextPath) => {
    const response = await fetch(buildApiMeFieldsUrl(contextPath), {
        method: 'GET',
        headers: {
            Authorization: basicAuth('admin', 'district'),
            Accept: 'application/json',
        },
        credentials: 'omit',
        cache: 'no-store',
    })

    if (response.status === 401 || response.status === 403) {
        return { authenticated: false, status: response.status }
    }

    if (!response.ok) {
        return {
            authenticated: null,
            status: response.status,
            error: `Unexpected HTTP ${response.status}`,
        }
    }

    let data
    try {
        data = await response.json()
    } catch (error) {
        return {
            authenticated: null,
            status: response.status,
            error: error.message || 'Unable to parse response',
        }
    }

    return {
        authenticated: data?.username === 'admin',
        username: data?.username || null,
        status: response.status,
    }
}

// Test seam — clears the memoized Promises. Not used in production code.
export const __resetApiMeCache = () => {
    headerPromisesByUrl.clear()
}
