import { findDecodedUrls } from './decodeLiterals'

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

// Is this URL the *start* of a string literal, or is it sitting inside prose?
//
// An address the app might actually use begins its literal:
//
//   fetch("https://api.example.com/x")      "  → address
//   `https://api.example.com/${id}`         `  → address
//   "https://api" + ".example.com"          "  → address, once folded
//
// A URL quoted inside a sentence does not, and never can be one — the runtime
// would have to slice the sentence apart first:
//
//   `… (probably due to https://bugs.chromium.org/…)`   space → mention
//
// That is the whole distinction, and it is decidable from one character. It
// removes the documentation and error-message URLs that bundled libraries
// carry — the Temporal polyfill alone cites four Chromium bug reports in its
// RangeError text — without touching anything reachable.
//
// Known limits, both erring towards calling something a mention: a URL that
// begins mid-literal after other text (`"?next=https://…"`) and one built by
// interpolation (`` `${base}https://…` ``) are both counted as mentions.
const QUOTES = new Set(['"', "'", '`'])

const beginsLiteral = (source, index) =>
    index > 0 && QUOTES.has(source[index - 1])

// The same question answered from the AST instead of one character of
// context, and answered from the literal's own text rather than from byte
// offsets.
//
// Offsets cannot be used here: the AST is parsed from the file as written,
// while URLs are matched against a normalized copy in which escape sequences
// have been decoded and split-up literals folded. Those two texts have
// different lengths, so an index into one means nothing in the other. Values
// are stable across both — a parser decodes \u002f to / exactly as the
// normalizer does — so the decision is made on values.
//
// A host is an address if some string literal in the file *starts* with a URL
// naming it. A host appearing only part-way through a literal is prose.
const addressHostsFrom = (ast) => {
    const hosts = new Set()
    for (const literal of ast.literals) {
        const re = new RegExp(URL_LIKE.source, 'i')
        const match = re.exec(literal.value)
        if (!match || match.index !== 0) {
            continue
        }
        const rest = match[2] || ''
        const end = rest.search(AUTHORITY_END)
        const host = normalizeHost(end === -1 ? rest : rest.slice(0, end))
        if (host && isHostLike(host)) {
            hosts.add(host)
        }
    }
    return hosts
}

// Hosts appearing in an already-decoded payload.
const hostsIn = (text) => {
    const out = new Set()
    const re = new RegExp(URL_LIKE.source, 'gi')
    let match
    while ((match = re.exec(text)) !== null) {
        const rest = match[2] || ''
        const end = rest.search(AUTHORITY_END)
        const host = normalizeHost(end === -1 ? rest : rest.slice(0, end))
        if (host && isHostLike(host)) {
            out.add(host)
        }
    }
    return [...out]
}

// A host worth reporting: dotted name with a plausible TLD, an IPv4 literal,
// or a bracketed IPv6 literal. Requiring the TLD shape is what keeps ordinary
// prose ("see //foo for details") and version strings out of the results.
const DOTTED_NAME = /^(?:[a-z0-9_-]+\.)+[a-z]{2,63}$/

// Names reserved by RFC 2606 and RFC 6761 as guaranteed never to resolve.
// They exist precisely so code can use them as placeholders, and libraries do:
// query-string parses relative URLs against `https://query-string.invalid`,
// because a base is required and no request must ever be made. A name that
// cannot resolve is not a destination, so reporting one is always a false
// positive.
const RESERVED_TLD = /\.(?:invalid|test|example|localhost)$/
const RESERVED_NAME = /^(?:www\.)?example\.(?:com|net|org)$/

const isReservedName = (host) =>
    RESERVED_TLD.test(host) || RESERVED_NAME.test(host)
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/
const IPV6 = /^\[[0-9a-f:.]+\]$/

const isHostLike = (host) =>
    !isReservedName(host) &&
    (DOTTED_NAME.test(host) || IPV4.test(host) || IPV6.test(host))

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
// How close a URL must sit to a connection-API call to count as reachable.
//
// Correlating per file overclaims badly. Capture's 6.5 MB chunk contains
// exactly three connection calls and seventeen external hosts; per file, all
// seventeen were labelled "reachable from code that opens connections",
// including a Leaflet marker PNG on a CDN, an OpenStreetMap attribution link
// and a JSON-Schema identifier. Measured distances in that file:
//
//   nominatim.openstreetmap.org      324    the geocoding API it really calls
//   dev.virtualearth.net             412    the other geocoding API
//   cdnjs.cloudflare.com          10,410    a marker icon
//   osm.org                       19,724    an attribution link
//   json-schema.org            1,280,083    a $schema identifier
//
// The two real API endpoints sit within 412 characters of a call; the nearest
// unrelated address is 25x further away. 2000 sits in that gap with room on
// both sides.
//
// This is a second filter, not the only one: proximity alone is noisy in
// dense minified code — in the maps bundle a documentation URL lands 252
// characters from a call — but those are prose mentions, which the
// address/mention rule has already removed before this applies.
//
// It under-claims by design. A bundler is free to put a URL in a config
// object far from the fetch that consumes it, and that reads as an
// observation rather than a warning. A warning that cannot be trusted is
// worse than one that is occasionally missing.
const DEFAULT_PROXIMITY_CHARS = 2000

// Character offsets of every connection-API token, used to decide whether a
// URL sits beside a call or merely in the same file.
const findSinkPositions = (source, confirmedIds) => {
    const positions = []
    for (const sink of SINKS) {
        if (confirmedIds && !confirmedIds.has(sink.id)) {
            continue
        }
        const re = new RegExp(sink.pattern.source, 'g')
        let match
        while ((match = re.exec(source)) !== null) {
            positions.push(match.index)
            if (match.index === re.lastIndex) {
                re.lastIndex += 1
            }
        }
    }
    return positions.sort((a, b) => a - b)
}

// Distance from `index` to the closest entry of a sorted position list.
const nearestDistance = (positions, index) => {
    if (positions.length === 0) {
        return Infinity
    }
    let lo = 0
    let hi = positions.length - 1
    let best = Infinity
    while (lo <= hi) {
        const mid = (lo + hi) >> 1
        best = Math.min(best, Math.abs(positions[mid] - index))
        if (positions[mid] < index) {
            lo = mid + 1
        } else {
            hi = mid - 1
        }
    }
    return best
}

// `ast` is the result of astAnalysis.analyzeSource, or null when the file
// could not be parsed. With it, two heuristics become facts: sink positions
// come from real call sites rather than a token match, and whether a URL is an
// address or prose is decided by where it sits in its literal rather than by
// the character before it. Without it, the text path runs exactly as before —
// a file that will not parse is still analyzed.
export const findEndpoints = (source, { proximityChars, ast } = {}) => {
    const normalized = normalizeSource(source)
    // Positions are taken from the normalized text so they line up with the
    // URL matches. When the AST is available it decides *which* sinks are
    // real — a `fetch` inside a string or a property named fetch is not a
    // call — and only those kinds contribute positions.
    const confirmed = ast
        ? new Set(ast.sinkCalls.map((call) => call.id))
        : null
    const sinkPositions = findSinkPositions(normalized, confirmed)
    const window = proximityChars ?? DEFAULT_PROXIMITY_CHARS
    const addressHosts = ast ? addressHostsFrom(ast) : null
    const byHost = new Map()

    // A URL recovered by decoding is always treated as an address: nothing
    // encodes a documentation link. `decoded` marks it so the finding can say
    // where it came from — that provenance is the finding.
    const decodedPayloads = findDecodedUrls(normalized, ast?.literals)

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
        const asAddress = addressHosts
            ? addressHosts.has(host)
            : beginsLiteral(normalized, match.index)
        const nearSink =
            nearestDistance(sinkPositions, match.index) <= window
        if (existing) {
            existing.count += 1
            existing.addressCount += asAddress ? 1 : 0
            existing.nearSink = existing.nearSink || nearSink
            if (existing.samples.length < 2 && !existing.samples.includes(sample)) {
                existing.samples.push(sample)
            }
            if (scheme && !existing.schemes.includes(scheme)) {
                existing.schemes.push(scheme)
            }
        } else {
            byHost.set(host, {
                host,
                addressCount: asAddress ? 1 : 0,
                nearSink,
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
    for (const { decoded, index } of decodedPayloads) {
        for (const host of hostsIn(decoded)) {
            const existing = byHost.get(host)
            const nearSink =
                nearestDistance(sinkPositions, index) <= window
            if (existing) {
                existing.count += 1
                existing.addressCount += 1
                existing.decoded = true
                existing.nearSink = existing.nearSink || nearSink
            } else {
                byHost.set(host, {
                    host,
                    addressCount: 1,
                    decoded: true,
                    nearSink,
                    schemes: [],
                    punycode: host.includes('xn--'),
                    ip: IPV4.test(host) || IPV6.test(host),
                    count: 1,
                    samples: [decoded.slice(0, 120)],
                })
            }
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
// The eight non-namespace hosts a platform bundle used to yield — fb.me,
// jedwatson.github.io, npms.io, cra.link, underscorejs.org, feross.org,
// openjsf.org, stackoverflow.com — were all documentation or licence links
// appearing once or twice. They no longer need naming: every one of them is a
// URL quoted inside prose, so the address/mention rule removes them on
// evidence rather than by an allowlist entry that has to be maintained and
// that widens the blind spot each time it grows.
//
// Hosts never reported, kept deliberately short.
//
// Two conditions, and a host must meet both:
//
//   1. It appears as an *address* in real bundles, so the mention filter
//      cannot remove it. Measured across nine DHIS2 2.43.1 bundles, only
//      three hosts do: www.w3.org (264 occurrences, SVG/XML namespaces),
//      reactjs.org (7, the minified error-decoder URL) and docs.dhis2.org.
//
//   2. A third party cannot publish content there. This is the condition
//      that matters, and it is why the list no longer contains github.com,
//      raw.githubusercontent.com, the npm registry, *.github.io, sourceforge
//      or stackoverflow.com. Those are precisely the hosts a payload would be
//      fetched from — raw.githubusercontent.com serves arbitrary file content
//      with permissive CORS — and allow-listing them would have made the one
//      case worth catching invisible. URL shorteners (fb.me, cra.link) are
//      out for the same reason: they resolve to somewhere an attacker picks.
//      apps.dhis2.org is out because the App Hub distributes code.
//
// Everything dropped from this list scored zero as an address in the same
// measurement, so removing them added no noise: the mention filter already
// accounted for every occurrence.
const ALLOWED_EXACT = new Set([
    // Namespace identifiers. Written into SVG and XML markup as identity, not
    // as somewhere to fetch from, and nobody else can publish at them.
    'www.w3.org',
    'w3.org',
    'schema.org',
    'purl.org',
    'ns.adobe.com',
    'creativecommons.org',
    'www.inkscape.org',
    // React builds its error-decoder link as a real URL literal, so the
    // mention filter does not catch it.
    'reactjs.org',
    'legacy.reactjs.org',
    'react.dev',
    // DHIS2's own documentation. Note that apps.dhis2.org is deliberately
    // absent: the App Hub serves application code, so a request to it is
    // worth seeing.
    'dhis2.org',
    'www.dhis2.org',
    'docs.dhis2.org',
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
                existing.addressCount += endpoint.addressCount || 0
                existing.files.add(file.src)
                existing.reachable = existing.reachable || Boolean(endpoint.nearSink)
                existing.decoded = existing.decoded || Boolean(endpoint.decoded)
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
                    addressCount: endpoint.addressCount || 0,
                    schemes: [...(endpoint.schemes || [])],
                    samples: [...endpoint.samples],
                    files: new Set([file.src]),
                    reachable: Boolean(endpoint.nearSink),
                    decoded: Boolean(endpoint.decoded),
                })
            }
        }
    }

    // A host that never once begins a string literal is named in prose, not
    // used as an address. Reported as a count rather than listed: it is not a
    // finding, but dropping it silently would overstate how clean the app is.
    const all = [...byHost.values()]
    // Named, not just counted. These are cheap to dismiss once seen — a
    // reader recognises momentjs.com and stackoverflow.com immediately —
    // whereas a bare count asks them to trust the classifier instead of
    // checking it. Sorted so the list is stable between runs.
    const mentionedOnly = all
        .filter((entry) => entry.addressCount === 0)
        .map((entry) => entry.host)
        .sort()

    const hosts = all
        .filter((entry) => entry.addressCount > 0)
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
    const decoded = hosts.filter((h) => h.decoded)
    // A host that only exists once a string is decoded was hidden on purpose.
    // Nothing legitimate encodes a URL to keep it out of a text search — and
    // measured across three real bundles, 1008 encoded-looking literals
    // yielded not one. This is the one endpoint finding that fails an app
    // rather than warning about it.
    const status =
        decoded.length > 0
            ? 'fail'
            : hosts.length === 0
            ? 'pass'
            : reachable.length > 0
            ? 'warning'
            : 'info'

    return {
        hosts,
        sinks: [...sinks],
        reachableCount: reachable.length,
        mentionedOnly,
        mentionedOnlyCount: mentionedOnly.length,
        status,
    }
}

