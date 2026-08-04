import i18n from '@dhis2/d2-i18n'
import { findScripts } from './findScripts'

// Hard cap on per-file size — JS-X-Ray on multi-megabyte minified bundles
// can lock the main thread for noticeable periods. Anything bigger gets a
// "skipped: too large" entry.
const MAX_FILE_BYTES = 5 * 1024 * 1024

// Warning kinds that carry near-zero signal in practice and are dropped
// unconditionally. We tried gating these on js-x-ray's `isMinified` flag,
// but that heuristic stays false on many real React/Vite bundles whose
// surviving DOM/Fiber identifier names (focusedElem, selectionRange,
// containerInfo, parentNode, …) push the identifier-length average back up.
//
//   unsafe-assign  — fires on any `obj[someProperty] = value` shape. Hits
//                    React reconciler bookkeeping (e.alternate, c.stateNode,
//                    r.tag, …) and DOM property writes constantly.
//   unsafe-regex   — safe-regex star-height check; matches moment's ISO-8601
//                    parser and similar bounded-but-nested patterns shipped
//                    by date/parsing libs.
//
// Strong-signal kinds (obfuscated-code, unsafe-import, unsafe-stmt,
// encoded-literal, weak-crypto, suspicious-literal) still flow through.
const NOISY_KINDS = new Set(['unsafe-assign', 'unsafe-regex'])

// Derive the DHIS2 context path from the running URL when systemInfo isn't
// available. Apps are served at <contextPath>/api/apps/<key>/... so the
// substring before "/api/apps/" is the contextPath.
const deriveContextPath = () => {
    if (typeof window === 'undefined') {
        return ''
    }
    const match = window.location.pathname.match(/^(.*?)\/api\/apps\//)
    return match ? match[1] : ''
}

// Build a URL to fetch the app's index.html. Preference:
//   1. app.baseUrl (newer DHIS2 returns absolute URL)
//   2. <contextPath>/api/apps/<key>
const buildIndexUrl = (app, contextPath) => {
    if (app.baseUrl) {
        return `${app.baseUrl.replace(/\/+$/, '')}/index.html`
    }
    const cp = (contextPath ?? deriveContextPath()).replace(/\/+$/, '')
    return `${cp}/api/apps/${app.key}/index.html`
}

// Scan a single installed app: list its scripts, fetch each, run the analyzer.
//
// Script srcs in the index.html are resolved against the index.html's final
// URL (post-redirect), using the standard URL constructor. This correctly
// handles:
//   - Relative srcs ("main.js", "./main.js", "assets/main.js") resolved
//     against the directory of the index.html
//   - Root-absolute srcs ("/assets/main.js") which are common in DHIS2 v42's
//     unified app shell — the bundle lives at the origin root, not at the
//     per-app path
//   - Server redirects (response.url differs from the requested URL)
//
// `analyze`, `fetchText`, and `contextPath` are test-injection seams.
export const scanApp = async ({
    app,
    analyze,
    fetchText = defaultFetchText,
    contextPath,
}) => {
    const indexRequestUrl = buildIndexUrl(app, contextPath)

    let indexResponse
    try {
        indexResponse = await fetchText(indexRequestUrl)
    } catch (err) {
        return {
            app,
            files: [],
            error: i18n.t('Could not fetch index.html: {{message}}', {
                message: err.message,
            }),
        }
    }

    const indexBaseUrl = indexResponse.finalUrl || indexRequestUrl
    const scripts = findScripts(indexResponse.text)
    if (scripts.length === 0) {
        return {
            app,
            files: [],
            note: i18n.t('No <script src> entries found in index.html'),
        }
    }

    const files = []
    for (const src of scripts) {
        const absoluteUrl = resolveUrl(src, indexBaseUrl)
        files.push(await scanFile(src, absoluteUrl, analyze, fetchText))
    }
    return { app, files }
}

// Resolve a script src against the served-index URL. URL constructor handles
// both root-absolute and relative inputs. Falls back to a plain join if the
// constructor throws (extremely unlikely with a well-formed base).
const resolveUrl = (src, base) => {
    try {
        return new URL(src, base).href
    } catch {
        return src
    }
}

const scanFile = async (src, absoluteUrl, analyze, fetchText) => {
    let response
    try {
        response = await fetchText(absoluteUrl)
    } catch (err) {
        return {
            src,
            error: i18n.t('Fetch failed: {{message}}', { message: err.message }),
        }
    }
    const source = response.text
    if (source.length > MAX_FILE_BYTES) {
        return {
            src,
            skipped: i18n.t('file exceeds size limit'),
            sizeBytes: source.length,
        }
    }
    try {
        const result = analyze(source)
        const warnings = (result?.warnings || []).filter(
            (w) => !NOISY_KINDS.has(w.kind)
        )
        return {
            src,
            warnings,
            isMinified: !!result?.isMinified,
            sizeBytes: source.length,
        }
    } catch (err) {
        return {
            src,
            error: i18n.t('Analyzer failed: {{message}}', {
                message: err.message,
            }),
        }
    }
}

// Fetch helper that returns both the body and the final URL (post-redirect).
// The final URL is needed to resolve script src attributes that may be
// relative to the served document, not the originally-requested URL.
const defaultFetchText = async (url) => {
    const response = await fetch(url, { credentials: 'include' })
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
    }
    return { text: await response.text(), finalUrl: response.url || url }
}
