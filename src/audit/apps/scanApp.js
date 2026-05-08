import { findScripts } from './findScripts'

// Hard cap on per-file size — JS-X-Ray on multi-megabyte minified bundles
// can lock the main thread for noticeable periods. Anything bigger gets a
// "skipped: too large" entry.
const MAX_FILE_BYTES = 5 * 1024 * 1024

const buildAppFileUrl = (app, file) => {
    const base = (app.baseUrl || `api/apps/${app.key}`).replace(/\/+$/, '')
    return `${base}/${file}`
}

// Scan a single installed app: list its scripts, fetch each, run the analyzer.
// `analyze` is the js-x-ray runASTAnalysis function (injected so tests don't
// need the real package). `fetchText(url)` returns the response body as a
// string; defaults to the global fetch.
export const scanApp = async ({
    app,
    analyze,
    fetchText = defaultFetchText,
}) => {
    let indexHtml
    try {
        indexHtml = await fetchText(buildAppFileUrl(app, 'index.html'))
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
        files.push(await scanFile(app, src, analyze, fetchText))
    }
    return { app, files }
}

const scanFile = async (app, src, analyze, fetchText) => {
    let source
    try {
        source = await fetchText(buildAppFileUrl(app, src))
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
