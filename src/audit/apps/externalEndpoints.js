// Which outside origins does an installed app's code reference, and can it
// actually talk to them?
//
// This is a raw-text check, and that is the whole point. Minifiers rename
// identifiers, hoist, inline and mangle structure — which is why the AST
// analysis is off by default (see scanLimits.enableCodeAnalysis) — but they
// do not rewrite string literals. A hostname that the code will one day pass
// to fetch() has to survive minification intact, because it is data, not
// code. So this check belongs in the same category as library detection and
// hashing: it works on the bytes the server served, it needs no parser, and
// what it reports is checkable by a human against the app's own network tab.
//
// The claim it makes is deliberately narrow. "This bundle contains the string
// api.example.com and also contains fetch()" is not "this app is malicious" —
// plenty of apps legitimately reach a tile server or a terminology service.
// It is "this app can send data somewhere that is not your DHIS2 instance",
// which is a fact an administrator of a health information system is entitled
// to know, and which nothing else in this audit reports.

// --- de-obfuscation ---------------------------------------------------------
//
// Everything here exists because a hostname can be written many ways that all
// mean the same thing to the browser. We normalize the text first and match
// second, so `https://evil.com`, `https:\/\/evil.com`, `https://EVIL.com.`,
// `https://user:pw@evil.com` and `"https://ev"+"il.com"` collapse to one
// finding for `evil.com` rather than four, or none.
//
// This is not a general deobfuscator and does not pretend to be. A host
// assembled at runtime — atob("ZXZpbC5jb20="), String.fromCharCode(...), a
// character-by-character array join — is out of reach of any string scan, and
// is left to the AST analyzer's encoded-literal finding. What is covered is
// the escaping that appears in real code: JSON-encoded strings, unicode and
// hex escapes, percent-encoding, and literal concatenation.

// \uXXXX and \xXX escapes. An obfuscator writing http...
// spells "http" without the string "http" ever appearing in the file.
const UNICODE_ESCAPE = /\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})/g

// Percent-encoded delimiters. %2F%2Fevil.com is a URL to any decoder that
// sees it, and is invisible to a scan looking for "//".
const PERCENT_ESCAPE = /%(2[0-9a-fA-F]|3[0-9a-fA-F])/g

// Adjacent string literals joined by +. Minifiers fold these; obfuscators
// introduce them. Bounded to a few passes so a pathological chain of
// thousands of fragments cannot dominate the scan.
const CONCAT = /(["'])([^"'\\\n\r]{0,120})\1\s*\+\s*(["'])([^"'\\\n\r]{0,120})\3/g
const CONCAT_PASSES = 3

const decodeEscapes = (text) =>
    text
        // \/ is by far the most common: any URL that has been through
        // JSON.stringify carries it.
        .replace(/\\\//g, '/')
        .replace(UNICODE_ESCAPE, (match, u, x) => {
            const code = parseInt(u || x, 16)
            // Only fold escapes back into characters that can appear in a
            // URL. Leaving the rest alone keeps this from mangling genuine
            // text (and from turning an escaped NUL into a real one in the scanned copy).
            return code >= 0x20 && code <= 0x7e ? String.fromCharCode(code) : match
        })
        .replace(PERCENT_ESCAPE, (match, hex) => {
            const code = parseInt(hex, 16)
            return code >= 0x20 && code <= 0x3f ? String.fromCharCode(code) : match
        })

const foldConcatenations = (text) => {
    let out = text
    for (let pass = 0; pass < CONCAT_PASSES; pass++) {
        const next = out.replace(CONCAT, (match, q1, a, q2, b) => `${q1}${a}${b}${q1}`)
        if (next === out) {
            break
        }
        out = next
    }
    return out
}

// Normalize once, scan the result. Kept as its own export so a test can show
// what the scanner actually sees.
export const normalizeSource = (source) =>
    typeof source === 'string' ? foldConcatenations(decodeEscapes(source)) : ''

// --- extraction -------------------------------------------------------------

// An absolute or protocol-relative URL. The authority is captured loosely and
// validated afterwards by isHostLike, because being strict here costs more in
// missed obfuscation than it saves in false positives.
//
// The scheme is matched generically rather than from a fixed list, so an
// unexpected one is reported instead of silently ignored — a URL this scanner
// cannot name is exactly the kind it should not drop. Schemes without an
// authority (data:, blob:, javascript:, about:) do not match, because they
// have no `//host` to match against. That is deliberate and load-bearing:
// data:image/svg+xml appears hundreds of times in a bundle carrying inline
// icons, and none of those are a destination.
//
// Protocol-relative matches must be preceded by a quote. Without that guard,
// every `// comment` in a license banner becomes a candidate.
const URL_LIKE = /(?:\b([a-z][a-z0-9+.-]{1,31}):\/\/|(?<=["'`])\/\/)([^\s"'`\\<>(){}[\],;]{1,300})/gi

// Where the authority ends and the path begins.
const AUTHORITY_END = /[/?#]/

// A host worth reporting: dotted name with a plausible TLD, an IPv4 literal,
// or a bracketed IPv6 literal. Requiring the TLD shape is what keeps ordinary
// prose ("see //foo for details") and version strings out of the results.
const DOTTED_NAME = /^(?:[a-z0-9_-]+\.)+[a-z]{2,63}$/
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/
const IPV6 = /^\[[0-9a-f:.]+\]$/

const isHostLike = (host) =>
    DOTTED_NAME.test(host) || IPV4.test(host) || IPV6.test(host)

// --- scheme classification --------------------------------------------------
//
// Every host carries the set of schemes it was seen with, and those become
// labels on the finding rather than findings of their own. A destination is
// one thing; how the app proposes to reach it is a property of that
// destination, and splitting them into separate lists would report the same
// URL twice.
//
// Only two schemes carry transport security. Everything else is either
// cleartext or unusual enough that an administrator should be told which one
// it was rather than have it bucketed.
const SECURE_SCHEMES = new Set(['https', 'wss'])
const CLEARTEXT_SCHEMES = new Set(['http', 'ws'])

// Note what is NOT examined here: the instance's own host. An app hardcoding
// http:// against its own server is a real problem, but it is the problem the
// DHIS2 audit's "HTTPS Connection Security" check already answers directly
// from window.location, and answering it twice from weaker evidence would
// only produce a second, less reliable verdict.
export const schemeFlags = (schemes = []) => ({
    // http:// or ws:// — readable and modifiable by anything on the path.
    cleartext: schemes.some((s) => CLEARTEXT_SCHEMES.has(s)),
    // Neither a secure nor a plain web scheme: ftp://, file://, telnet://, or
    // a custom application scheme. Not necessarily dangerous, but never
    // ordinary inside a DHIS2 app bundle.
    nonStandard: schemes.some(
        (s) => !SECURE_SCHEMES.has(s) && !CLEARTEXT_SCHEMES.has(s)
    ),
})

// Reduce an authority to a comparable host.
//
// Strips credentials (https://user:pass@host — the userinfo is a classic way
// to make a URL read as though it points somewhere else), drops the port,
// lowercases, and removes the trailing dot of a fully-qualified name, so
// `EVIL.com.` and `evil.com` are one host and not two.
export const normalizeHost = (authority) => {
    if (!authority) {
        return null
    }
    let host = authority
    const at = host.lastIndexOf('@')
    if (at !== -1) {
        host = host.slice(at + 1)
    }
    // Port, but not the colons inside a bracketed IPv6 literal.
    if (!host.startsWith('[')) {
        const colon = host.indexOf(':')
        if (colon !== -1) {
            host = host.slice(0, colon)
        }
    } else {
        const close = host.indexOf(']')
        if (close !== -1) {
            host = host.slice(0, close + 1)
        }
    }
    host = host.toLowerCase().replace(/\.+$/, '')
    return host || null
}

// Extract every referenced host from one file's source.
//
// Returns [{ host, scheme, punycode, ip, samples }] where `samples` holds up
// to a couple of the literal forms the host appeared in, so a report can show
// the reader what was actually in the file rather than only the normalized
// name.
export const findEndpoints = (source) => {
    const normalized = normalizeSource(source)
    const byHost = new Map()

    URL_LIKE.lastIndex = 0
    let match
    while ((match = URL_LIKE.exec(normalized)) !== null) {
        const scheme = (match[1] || '').toLowerCase() || null
        const rest = match[2] || ''
        const end = rest.search(AUTHORITY_END)
        const authority = end === -1 ? rest : rest.slice(0, end)
        const host = normalizeHost(authority)
        if (!host || !isHostLike(host)) {
            continue
        }
        const existing = byHost.get(host)
        const sample = match[0].slice(0, 120)
        if (existing) {
            existing.count += 1
            if (existing.samples.length < 2 && !existing.samples.includes(sample)) {
                existing.samples.push(sample)
            }
            if (scheme && !existing.schemes.includes(scheme)) {
                existing.schemes.push(scheme)
            }
        } else {
            byHost.set(host, {
                host,
                schemes: scheme ? [scheme] : [],
                // An xn-- label is a non-ASCII name in disguise. Legitimate
                // in a bundle serving an IDN, and also how a lookalike domain
                // hides from a reader comparing strings.
                punycode: host.includes('xn--'),
                // A hardcoded address rather than a name: no DNS record to
                // inspect, no certificate name to check.
                ip: IPV4.test(host) || IPV6.test(host),
                count: 1,
                samples: [sample],
            })
        }
    }
    return [...byHost.values()]
}

// --- capability detection ---------------------------------------------------
//
// A referenced host only matters if the app can reach one. These are the APIs
// that actually open a connection, and they are detectable in minified code
// for the same reason the hosts are: they are global or DOM names, so a
// minifier cannot rename them without breaking the program.
//
// `fetch(` will also match a local helper called fetch, and createElement
// ("script") will match a legitimate lazy-loader. That is acceptable: this
// half of the check is not the finding, it is what decides whether a host
// list is worth a warning or an observation.
//
// It is textual, so it also matches an app that merely *names* these APIs.
// Measured on this app's own bundle, which reports all nine — because the
// patterns below are themselves string literals in it. That costs nothing:
// a sink only escalates a host that shares its file, and an app naming an
// API without a matching external host still reports pass.
const SINKS = [
    { id: 'fetch', pattern: /\bfetch\s*\(/, label: 'fetch()' },
    {
        id: 'xhr',
        pattern: /\bXMLHttpRequest\b/,
        label: 'XMLHttpRequest',
    },
    { id: 'websocket', pattern: /\bWebSocket\s*\(/, label: 'WebSocket' },
    {
        id: 'beacon',
        pattern: /\bsendBeacon\s*\(/,
        label: 'navigator.sendBeacon()',
    },
    {
        id: 'eventsource',
        pattern: /\bEventSource\s*\(/,
        label: 'EventSource',
    },
    {
        id: 'importscripts',
        pattern: /\bimportScripts\s*\(/,
        label: 'importScripts()',
    },
    {
        id: 'serviceworker',
        pattern: /serviceWorker\s*\.\s*register\s*\(/,
        label: 'serviceWorker.register()',
    },
    {
        id: 'script-injection',
        pattern: /createElement\s*\(\s*(["'`])script\1/i,
        label: "createElement('script')",
    },
    {
        id: 'webrtc',
        pattern: /\bRTCPeerConnection\b/,
        label: 'RTCPeerConnection',
    },
]

// Which connection-opening APIs appear in this source.
export const findSinks = (source) => {
    if (typeof source !== 'string') {
        return []
    }
    return SINKS.filter((sink) => sink.pattern.test(source)).map((sink) => sink.id)
}

export const sinkLabel = (id) => SINKS.find((s) => s.id === id)?.label || id

// --- allowlist --------------------------------------------------------------
//
// Hosts that appear in essentially every bundle without representing a
// connection the app can or will make. Two distinct kinds, kept separate
// because they are benign for different reasons:
//
//   Namespace URIs are identifiers, not addresses. `http://www.w3.org/2000/
//   svg` is required by every inline SVG in every React app and is never
//   fetched. Measured on @nodesecure/js-x-ray v16 against DHIS2 bundles, 22
//   of its 40 shady-link hits were this single string — which is why that
//   check was rejected wholesale rather than allowlisted. This is the
//   allowlist it needed.
//
//   Documentation links appear in error messages and license banners. React
//   alone ships a dozen react.dev URLs in its production build.
//
// Deliberately NOT here: CDNs (unpkg, jsdelivr, cdnjs), analytics, tile and
// font servers. Those are real outbound connections. An app that loads code
// or data from a CDN is exactly what this check exists to surface, however
// ordinary the practice is elsewhere — on an air-gapped or
// patient-data-bearing instance it is a finding, not a detail.
// Every entry below the namespace block was observed in a real DHIS2 platform
// bundle: this app's own production build, 1.8 MB across 7 chunks. The whole
// of its real application code — React, @dhis2/ui, the app itself — yielded
// exactly eight non-namespace external hosts, every one a documentation or
// licence link appearing once or twice:
//
//   fb.me (prop-types)            jedwatson.github.io (classnames)
//   npms.io (a ponyfill README)   cra.link (create-react-app)
//   underscorejs.org (LICENSE)    feross.org (safe-buffer)
//   openjsf.org, stackoverflow.com (comments in vendor code)
//
// That is the entire steady-state noise floor for a platform app, which is
// what makes this check worth having: after this allowlist, a DHIS2 app that
// reports an external host is saying something unusual.
const ALLOWED_EXACT = new Set([
    // XML/SVG/XHTML namespaces. Identifiers, not addresses — never fetched.
    'www.w3.org',
    'w3.org',
    'schema.org',
    'purl.org',
    'ns.adobe.com',
    'sodipodi.sourceforge.net',
    'www.inkscape.org',
    'creativecommons.org',
    // Specification and documentation links in error messages
    'developer.mozilla.org',
    'react.dev',
    'reactjs.org',
    'legacy.reactjs.org',
    'facebook.github.io',
    'fb.me',
    'redux.js.org',
    'vitejs.dev',
    'rollupjs.org',
    'webpack.js.org',
    'cra.link',
    'tc39.es',
    'developers.google.com',
    'momentjs.com',
    'lodash.com',
    'underscorejs.org',
    'day.js.org',
    'jedwatson.github.io',
    'openjsf.org',
    'feross.org',
    'npms.io',
    'stackoverflow.com',
    // License headers
    'opensource.org',
    'www.apache.org',
    'apache.org',
    'www.gnu.org',
    'www.mozilla.org',
    'unlicense.org',
    // Package and source metadata
    'github.com',
    'www.npmjs.com',
    'npmjs.com',
    'registry.npmjs.org',
    'raw.githubusercontent.com',
    // DHIS2's own documentation and app hub
    'dhis2.org',
    'www.dhis2.org',
    'docs.dhis2.org',
    'apps.dhis2.org',
])

// Localhost and the loopback range: a development leftover, not an external
// destination. Worth neither a warning nor the noise of reporting it.
const LOOPBACK = /^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/

export const isAllowedHost = (host, extraAllowed = []) =>
    ALLOWED_EXACT.has(host) ||
    LOOPBACK.test(host) ||
    extraAllowed.some(
        (allowed) =>
            host === allowed ||
            (allowed.startsWith('.') && host.endsWith(allowed))
    )

// --- summarization ----------------------------------------------------------

// The host of the DHIS2 instance itself, derived from any URL on it.
export const originHost = (url) => {
    try {
        return new URL(url).hostname.toLowerCase()
    } catch {
        return null
    }
}

// Roll a scanned app's files up into one answer about external connectivity.
//
// `instanceHost` is the DHIS2 instance's own hostname: references to it are
// the app talking to its own server, which is the entire normal case and is
// never reported.
//
// A host is marked `reachable` when it appears in the *same file* as a
// connection API. Correlating per file rather than per app is what keeps this
// check honest, and it is measured rather than assumed: this app's own bundle
// splits into a 640 KB chunk that has fetch/XHR and only documentation links,
// and a 368 KB chunk of vendored advisory data holding 101 external hosts and
// no connection API at all. Rolled up per app, those combine into "101 hosts
// and it can reach them", which is false. Per file, the data blob is
// correctly an observation and the code chunk is correctly clean.
//
// The trade is real and worth stating: a bundler is free to put a URL in one
// chunk and the fetch that uses it in another, and that case is reported as
// an observation rather than a warning. Under-claiming beats a warning that
// cannot be trusted.
//
// Status reflects what can actually be concluded:
//   warning  an external host sits in a file that can open a connection
//   info     external hosts, none co-located with a connection API — strings
//            worth seeing, not evidence of a connection
//   pass     nothing outside the instance
export const summarizeExternalEndpoints = (
    files,
    { instanceHost, allowedHosts = [] } = {}
) => {
    const byHost = new Map()
    const sinks = new Set()

    for (const file of files || []) {
        const fileSinks = file.sinks || []
        for (const sink of fileSinks) {
            sinks.add(sink)
        }
        for (const endpoint of file.endpoints || []) {
            if (endpoint.host === instanceHost) {
                continue
            }
            if (isAllowedHost(endpoint.host, allowedHosts)) {
                continue
            }
            const existing = byHost.get(endpoint.host)
            if (existing) {
                existing.count += endpoint.count
                existing.files.add(file.src)
                existing.reachable = existing.reachable || fileSinks.length > 0
                // One host can be reached over several schemes across an
                // app's chunks. Keeping the union means a host seen once over
                // https and once over http is still labelled cleartext.
                for (const scheme of endpoint.schemes || []) {
                    if (!existing.schemes.includes(scheme)) {
                        existing.schemes.push(scheme)
                    }
                }
                for (const sample of endpoint.samples) {
                    if (existing.samples.length < 2 && !existing.samples.includes(sample)) {
                        existing.samples.push(sample)
                    }
                }
            } else {
                byHost.set(endpoint.host, {
                    ...endpoint,
                    schemes: [...(endpoint.schemes || [])],
                    samples: [...endpoint.samples],
                    files: new Set([file.src]),
                    reachable: fileSinks.length > 0,
                })
            }
        }
    }

    const hosts = [...byHost.values()]
        .map((entry) => ({
            ...entry,
            files: [...entry.files],
            // Derived last, from the union of schemes across every file the
            // host appeared in.
            ...schemeFlags(entry.schemes),
        }))
        // Reachable hosts first — those are the ones to look at — then by how
        // often they appear, then alphabetically so the order is stable.
        .sort(
            (a, b) =>
                Number(b.reachable) - Number(a.reachable) ||
                b.count - a.count ||
                a.host.localeCompare(b.host)
        )

    const reachable = hosts.filter((h) => h.reachable)
    const status =
        hosts.length === 0 ? 'pass' : reachable.length > 0 ? 'warning' : 'info'

    return { hosts, sinks: [...sinks], reachableCount: reachable.length, status }
}

