import i18n from '@dhis2/d2-i18n'
import { findEntryAssets } from './findScripts'
import { resolveScanLimits } from './scanLimits'

// Size and crawl bounds come from the audit config — see scanLimits.js for
// each default and the measurement behind it.


// DHIS2 2.42+ serves every app through the global app shell: a request for
// the app's index.html answers 302 → /apps/<key>, which returns the *shell's*
// index.html. The shell then loads the app dynamically, so its index.html
// links only the shell bundle. Scanning that gives every app on the instance
// an identical result set drawn from the shell's own vendor code rather than
// from the app itself.
//
// `?redirect=false` is the shell bypass. Measured on the public play
// instances, authenticated, for both the /api/apps/<key>/ and the legacy
// /dhis-web-<name>/ form (the latter is what /api/apps reports as baseUrl for
// bundled apps on every version below):
//
//   2.40.12    plain 200 (app's own index)  |  bypass 200, parameter ignored
//   2.41.9     plain 200 (app's own index)  |  bypass 200, parameter ignored
//   2.42.5.1   plain 302 → /apps/<key>      |  bypass 200 (app's own index)
//   2.43.1     plain 302 → /apps/<key>      |  bypass 200 (app's own index)
//
// So the parameter is a no-op before 2.42 and the fix from 2.42 on — safe to
// send unconditionally.
const SHELL_BYPASS = 'redirect=false'

const withBypass = (url) => url + (url.includes('?') ? '&' : '?') + SHELL_BYPASS

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

// The directory an app's files live under — used to resolve relative refs
// and to bound the module crawl.
const dirOf = (url) => url.replace(/[?#].*$/, '').replace(/[^/]*$/, '')

// Did the server redirect us out of the app's own directory? If so we are
// looking at some other document, not the app, and any findings would belong
// to that document instead.
const redirectedAway = (requestedUrl, finalUrl) => {
    if (!finalUrl) {
        return false
    }
    const final = finalUrl.replace(/[?#].*$/, '')
    return !final.startsWith(dirOf(requestedUrl))
}

// Where did it actually send us? Reporting "the app shell was served" for
// what is really an expired session would send an admin looking in the wrong
// place — and a session expiring mid-run is the likelier cause, since it hits
// every remaining app at once. Covers both the modern login app and 2.40's
// legacy login.action.
const isLoginRedirect = (finalUrl) =>
    /(\/dhis-web-login|\/login\/?($|[?#])|login\.action)/i.test(finalUrl)

// Scan a single installed app: resolve its JS entry points, walk the module
// graph, and run the analyzer over each file.
//
// Refs are resolved against the index.html's final URL (post-redirect) using
// the standard URL constructor, which correctly handles:
//   - Relative refs ("main.js", "./main.js", "assets/main.js") resolved
//     against the directory of the index.html
//   - Root-absolute refs ("/assets/main.js") which are common in DHIS2 v42's
//     unified app shell — the bundle lives at the origin root, not at the
//     per-app path
//   - Server redirects (response.url differs from the requested URL)
//
// `analyze`, `fetchText`, and `contextPath` are test-injection seams.
export const scanApp = async ({
    app,
    processFile,
    fetchText = defaultFetchText,
    contextPath,
    config,
}) => {
    const limits = resolveScanLimits(config)
    const indexRequestUrl = withBypass(buildIndexUrl(app, contextPath))

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

    // Bail out rather than analyze somebody else's document. Reporting this
    // honestly as "not scanned" beats reporting the shell's vendor code once
    // per app under 45 different app names.
    if (redirectedAway(indexRequestUrl, indexBaseUrl)) {
        return isLoginRedirect(indexBaseUrl)
            ? {
                  app,
                  files: [],
                  notScanned: 'login-redirect',
                  note: i18n.t(
                      'index.html redirected to the login page ({{url}}) — the session has probably expired, so nothing was analyzed. Sign in again and re-run.',
                      { url: indexBaseUrl }
                  ),
              }
            : {
                  app,
                  files: [],
                  notScanned: 'shell-redirect',
                  note: i18n.t(
                      'index.html redirected to {{url}} — the DHIS2 app shell was served instead of the app, so the app’s own code could not be located.',
                      { url: indexBaseUrl }
                  ),
              }
    }

    const entries = findEntryAssets(indexResponse.text)
    if (entries.length === 0) {
        return {
            app,
            files: [],
            notScanned: 'no-entries',
            note: i18n.t('No JavaScript entry points found in index.html'),
        }
    }

    return {
        app,
        files: await crawl({
            entries,
            indexBaseUrl,
            fetchText,
            limits,
            processFile,
        }),
    }
}

// Breadth-first walk over the app's module graph, starting from the entry
// points declared by index.html.
const crawl = async ({
    entries,
    indexBaseUrl,
    fetchText,
    limits,
    processFile,
}) => {
    const appDir = dirOf(indexBaseUrl)
    const queue = entries.map((src) => ({
        src,
        url: resolveUrl(src, indexBaseUrl),
        discovered: false,
    }))
    const seen = new Set(queue.map((item) => item.url))
    const files = []
    let totalBytes = 0
    let consecutiveUnfetchable = 0

    while (queue.length > 0) {
        if (
            files.length >= limits.maxFiles ||
            totalBytes >= limits.maxTotalBytes
        ) {
            // Never truncate silently — an unreported cap reads as "we looked
            // at everything and it was fine".
            files.push({
                src: i18n.t('{{count}} further file(s)', {
                    count: queue.length,
                }),
                skipped: i18n.t('crawl limit reached'),
            })
            break
        }

        const item = queue.shift()
        const file = await scanFile(item, { fetchText, limits, processFile })
        files.push(file)
        totalBytes += file.sizeBytes || 0

        // Specifiers are found by scanning string literals, which picks up
        // tables of paths that are not modules of this app at all — moment's
        // locale list is the worst case, and produced 856 candidate files for
        // one app, every one a request that comes back as a 404 page. A real
        // module graph never has a run of dead ends, so a run of them means
        // we have walked into such a table and should stop.
        consecutiveUnfetchable = file.unfetchable ? consecutiveUnfetchable + 1 : 0
        if (consecutiveUnfetchable >= limits.maxConsecutiveUnfetchable) {
            files.push({
                src: i18n.t('{{count}} further file(s)', {
                    count: queue.length,
                }),
                skipped: i18n.t(
                    'stopped after {{count}} discovered paths in a row could not be fetched',
                    { count: consecutiveUnfetchable }
                ),
            })
            break
        }

        // Only follow imports out of files we actually read, and only within
        // the app's own directory — a root-absolute entry may legitimately
        // live elsewhere, but its transitive imports are not ours to crawl.
        for (const spec of file.imports || []) {
            const url = resolveUrl(spec, item.url)
            if (!seen.has(url) && url.startsWith(appDir)) {
                seen.add(url)
                queue.push({ src: spec, url, discovered: true })
            }
        }
    }
    return files
}

// Resolve a ref against a base URL. URL constructor handles both
// root-absolute and relative inputs. Falls back to the raw ref if the
// constructor throws (extremely unlikely with a well-formed base).
const resolveUrl = (src, base) => {
    try {
        return new URL(src, base).href
    } catch {
        return src
    }
}

// Cheap content sniff. A JS module never begins with markup; an error page,
// an SPA fallback or a directory listing always does.
const looksLikeHtml = (source) => /^\s*(<!doctype|<html|<\?xml|<)/i.test(source)

const scanFile = async ({ src, url, discovered }, { fetchText, limits, processFile }) => {
    let response
    try {
        response = await fetchText(url)
    } catch (err) {
        // A specifier found by literal scanning may not be a real module
        // path. Don't report that as an error against the app.
        if (discovered) {
            return { src, skipped: i18n.t('not fetchable'), unfetchable: true }
        }
        return {
            src,
            error: i18n.t('Fetch failed: {{message}}', { message: err.message }),
        }
    }
    const source = response.text
    // DHIS2 answers a missing app path with an HTML page rather than a 404,
    // so a specifier that points at nothing comes back as markup. Feeding
    // that to the analyzer produced "Analyzer failed: Unexpected token '<'"
    // and turned the whole app red. Not JavaScript is a skip, not an error.
    if (looksLikeHtml(source)) {
        return {
            src,
            skipped: i18n.t('server did not return JavaScript'),
            sizeBytes: source.length,
            unfetchable: discovered,
        }
    }

    // Too large to parse, but still worth hashing and matching against the
    // library signatures — the processor skips only the analysis.
    const skipAnalysis = source.length > limits.maxFileBytes

    const { hash, libraries, imports, warnings, isMinified, analyzeError } =
        await processFile({ src, source, skipAnalysis })

    if (skipAnalysis) {
        return {
            src,
            hash,
            libraries,
            imports,
            skipped: i18n.t('file exceeds size limit'),
            sizeBytes: source.length,
        }
    }
    if (analyzeError) {
        return {
            src,
            hash,
            libraries,
            imports,
            sizeBytes: source.length,
            error: i18n.t('Analyzer failed: {{message}}', {
                message: analyzeError,
            }),
        }
    }
    return {
        src,
        warnings,
        imports,
        hash,
        libraries,
        isMinified,
        sizeBytes: source.length,
    }
}

// Fetch helper that returns both the body and the final URL (post-redirect).
// The final URL is needed to resolve refs that may be relative to the served
// document, not the originally-requested URL.
const defaultFetchText = async (url) => {
    const response = await fetch(url, { credentials: 'include' })
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
    }
    return { text: await response.text(), finalUrl: response.url || url }
}
