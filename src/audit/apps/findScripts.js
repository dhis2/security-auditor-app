// Extract <script src=...> references from a fetched index.html document.
// Returns an array of resolved relative paths (without the leading slash) so
// callers can fetch them via `apps/<key>/<path>`. External http(s) script
// sources are returned as-is so the caller can decide what to do (we skip
// remote scripts in the runner — we can only analyze same-origin code).
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
        // Strip leading "./" and any query/hash fragments.
        const cleaned = trimmed
            .replace(/^\.\//, '')
            .replace(/^\/+/, '')
            .replace(/[?#].*$/, '')
        if (cleaned) {
            out.push(cleaned)
        }
    }
    return out
}
