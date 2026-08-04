// Extract the JavaScript entry points from a fetched index.html document.
// Returns the raw src/href strings (relative or absolute) — the caller
// resolves them against the response URL via the URL constructor, which
// correctly handles:
//   "main.js"            → relative to the index.html location
//   "./main.js"          → same as above
//   "/assets/main.js"    → absolute path from origin root (used by DHIS2's
//                           unified app shell on v42+)
//   "assets/main.js"     → relative to the index.html directory
// We strip query/hash fragments (those reference the same file). External
// http(s) sources are filtered out — we can't fetch and analyze cross-origin
// code.

// Drop cross-origin refs, strip query/hash, skip empties.
const cleanRef = (raw) => {
    if (!raw) {
        return null
    }
    const trimmed = raw.trim()
    // Skip remote refs — we can't fetch and analyze cross-origin code.
    if (/^https?:\/\//i.test(trimmed) || trimmed.startsWith('//')) {
        return null
    }
    const cleaned = trimmed.replace(/[?#].*$/, '')
    return cleaned || null
}

const parse = (html) => {
    if (!html || typeof html !== 'string') {
        return null
    }
    return new DOMParser().parseFromString(html, 'text/html')
}

const collect = (doc, selector, attribute) => {
    const out = []
    for (const el of doc.querySelectorAll(selector)) {
        const cleaned = cleanRef(el.getAttribute(attribute))
        if (cleaned) {
            out.push(cleaned)
        }
    }
    return out
}

export const findScripts = (html) => {
    const doc = parse(html)
    return doc ? collect(doc, 'script[src]', 'src') : []
}

// Vite emits <link rel="modulepreload"> for every module in the entry's
// static import graph. Those files are app code that never appears as a
// <script src>, so without this the scan sees only the entry stub — on
// several DHIS2 apps (maps, data-visualizer) that stub is ~1 KB of lazy
// import glue and the real 600+ KB bundle goes unexamined.
export const findModulePreloads = (html) => {
    const doc = parse(html)
    if (!doc) {
        return []
    }
    // rel can carry multiple tokens ("preload modulepreload"), so match the
    // token rather than the exact attribute value.
    return collect(doc, 'link[rel~="modulepreload"][href]', 'href')
}

// All JS entry points declared by the document, de-duplicated, scripts first.
export const findEntryAssets = (html) => [
    ...new Set([...findScripts(html), ...findModulePreloads(html)]),
]
