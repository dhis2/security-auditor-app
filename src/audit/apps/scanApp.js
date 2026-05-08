import { findScripts } from './findScripts'

// Hard cap on per-file size — JS-X-Ray on multi-megabyte minified bundles
// can lock the main thread for noticeable periods. Anything bigger gets a
// "skipped: too large" entry.
const MAX_FILE_BYTES = 5 * 1024 * 1024

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

// Build an absolute path (or absolute URL) for a file inside an installed
// app. Preference order:
//   1. app.baseUrl from /api/apps (newer DHIS2 versions return an absolute URL)
//   2. <contextPath>/api/apps/<key>
// We never use a relative URL — relative resolution against the running app's
// own document URL would point inside this app, not the target app.
const buildAppFileUrl = (app, file, contextPath) => {
    if (app.baseUrl) {
        return `${app.baseUrl.replace(/\/+$/, '')}/${file}`
    }
    const cp = (contextPath ?? deriveContextPath()).replace(/\/+$/, '')
    return `${cp}/api/apps/${app.key}/${file}`
}

// Scan a single installed app: list its scripts, fetch each, run the analyzer.
// `analyze` is the js-x-ray runASTAnalysis function (injected so tests don't
// need the real package). `fetchText(url)` returns the response body as a
// string; defaults to the global fetch.
// `contextPath` is the DHIS2 instance's context path (from system/info),
// passed through so URL construction works on instances mounted at /dhis
// or any other subpath. If not supplied, it's derived from window.location.
export const scanApp = async ({
    app,
    analyze,
    fetchText = defaultFetchText,
    contextPath,
}) => {
    let indexHtml
    try {
        indexHtml = await fetchText(buildAppFileUrl(app, 'index.html', contextPath))
    } catch (err) {
        return {
            app,
            files: [],
            error: `Could not fetch index.html: ${err.message}`,
        }
    }

    const scripts = findScripts(indexHtml)
    if (scripts.length === 0) {
        return {
            app,
            files: [],
            note: 'No <script src> entries found in index.html',
        }
    }

    const files = []
    for (const src of scripts) {
        files.push(await scanFile(app, src, analyze, fetchText, contextPath))
    }
    return { app, files }
}

const scanFile = async (app, src, analyze, fetchText, contextPath) => {
    let source
    try {
        source = await fetchText(buildAppFileUrl(app, src, contextPath))
    } catch (err) {
        return { src, error: `Fetch failed: ${err.message}` }
    }
    if (source.length > MAX_FILE_BYTES) {
        return {
            src,
            skipped: 'file exceeds size limit',
            sizeBytes: source.length,
        }
    }
    try {
        const result = analyze(source)
        return {
            src,
            warnings: result?.warnings || [],
            isMinified: !!result?.isMinified,
            sizeBytes: source.length,
        }
    } catch (err) {
        return { src, error: `Analyzer failed: ${err.message}` }
    }
}

const defaultFetchText = async (url) => {
    const response = await fetch(url, { credentials: 'include' })
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
    }
    return response.text()
}
