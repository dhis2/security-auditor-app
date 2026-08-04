// Extract <script src=...> values from a fetched index.html document. Returns
// the raw src strings (relative or absolute) — the caller resolves them
// against the response URL via the URL constructor, which correctly handles:
//   "main.js"            → relative to the index.html location
//   "./main.js"          → same as above
//   "/assets/main.js"    → absolute path from origin root (used by DHIS2's
//                           unified app shell on v42+)
//   "assets/main.js"     → relative to the index.html directory
// We strip query/hash fragments (those reference the same file). External
// http(s) script sources are filtered out — we can't fetch and analyze
// cross-origin code.
export const findScripts = (html) => {
    if (!html || typeof html !== 'string') {
        return []
    }
    const doc = new DOMParser().parseFromString(html, 'text/html')
    const scripts = doc.querySelectorAll('script[src]')
    const out = []
    for (const el of scripts) {
        const src = el.getAttribute('src')
        if (!src) {
            continue
        }
        const trimmed = src.trim()
        // Skip remote scripts — we can't fetch and analyze cross-origin code.
        if (/^https?:\/\//i.test(trimmed) || trimmed.startsWith('//')) {
            continue
        }
        const cleaned = trimmed.replace(/[?#].*$/, '')
        if (cleaned) {
            out.push(cleaned)
        }
    }
    return out
}
