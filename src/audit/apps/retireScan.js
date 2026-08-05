// A port of Retire.js's matching algorithm, sized for this app.
//
// Retire.js identifies known-vulnerable JavaScript libraries by pattern, then
// maps the detected version to published advisories. That is a different kind
// of claim from anything the AST analyzer makes: "this bundle contains lodash
// 4.17.21, which is affected by CVE-2021-23337" is checkable and actionable,
// where "this file contains a call to Function()" is not.
//
// Crucially it still works after bundling. Measured on DHIS2 2.43.1 app
// bundles, it identifies react-dom, moment.js and lodash inside 600 KB of
// minified Vite output, and distinguishes the five apps carrying a vulnerable
// lodash from the three that do not.
//
// The upstream implementation (retire/lib/retire.js, Apache-2.0) is a Node
// CLI that reads from disk. This is the same algorithm over content we
// already have in memory. Behaviour is intentionally identical, including the
// order extractors are tried in and the `.min` suffix stripping — divergence
// would mean our findings could not be checked against retire.js itself.

// Upstream substitutes this for the §§version§§ placeholder. Note the
// escaping: retire.js performs the substitution on the repository's raw JSON
// *text*, so its replacement carries a doubled backslash that JSON.parse then
// collapses. We substitute into already-parsed strings, so we insert the
// collapsed form directly.
const VERSION_PATTERN = '[0-9][0-9.a-z_\\-]+'
const PLACEHOLDER = /§§version§§/g

// Walk the parsed repository and expand the placeholder wherever it appears.
export const expandVersionPlaceholders = (value) => {
    if (typeof value === 'string') {
        return value.replace(PLACEHOLDER, VERSION_PATTERN)
    }
    if (Array.isArray(value)) {
        return value.map(expandVersionPlaceholders)
    }
    if (value && typeof value === 'object') {
        const out = {}
        for (const [key, inner] of Object.entries(value)) {
            out[key] = expandVersionPlaceholders(inner)
        }
        return out
    }
    return value
}

// Run a global regex to exhaustion, collecting a chosen group.
//
// Hardened against a pattern that can match the empty string: with the `g`
// flag a zero-length match leaves lastIndex unmoved and exec() loops forever.
// Upstream has no such guard; a hang inside an audit tool that is scanning
// attacker-influenced content is not acceptable.
const execAll = (regex, data, onMatch) => {
    const results = []
    let match
    while ((match = regex.exec(data)) !== null) {
        results.push(onMatch(match))
        if (match.index === regex.lastIndex) {
            regex.lastIndex += 1
        }
    }
    return results
}

const simpleMatch = (pattern, data) =>
    execAll(new RegExp(pattern, 'g'), data, (m) => m[1]).filter(
        (v) => v !== undefined
    )

// `filecontentreplace` patterns have the form /regex/replacement/ and build
// the version from the replacement expression. This is what matches minified
// code, where the version survives as a bare string literal rather than in a
// comment banner.
const replacementMatch = (pattern, data) => {
    const parts = /^\/(.*[^\\])\/([^/]+)\/$/.exec(pattern)
    if (!parts) {
        return []
    }
    const [, source, replacement] = parts
    return execAll(new RegExp(source, 'g'), data, (m) =>
        m[0].replace(new RegExp(source), replacement)
    )
}

// `filename` patterns are anchored against the last path segment.
const filenameMatch = (pattern, data) =>
    simpleMatch(`^${pattern}$`, String(data).split(/[/\\]/).pop())

const MATCHERS = {
    filename: filenameMatch,
    filecontent: simpleMatch,
    filecontentreplace: replacementMatch,
    uri: simpleMatch,
}

const uniq = (results) => {
    const seen = new Set()
    return results.filter((r) => {
        const key = `${r.component} ${r.version}`
        if (seen.has(key)) {
            return false
        }
        seen.add(key)
        return true
    })
}

const scan = (data, extractor, components) => {
    const matcher = MATCHERS[extractor]
    const detected = []
    for (const [component, entry] of Object.entries(components)) {
        const patterns = entry.extractors?.[extractor]
        if (!patterns) {
            continue
        }
        for (const pattern of patterns) {
            let matches
            try {
                matches = matcher(pattern, data)
            } catch {
                // A malformed pattern must not abort the whole scan.
                continue
            }
            for (const raw of matches) {
                if (!raw) {
                    continue
                }
                detected.push({
                    component,
                    version: raw.replace(/(\.|-)min$/, ''),
                    detection: extractor,
                })
            }
        }
    }
    return uniq(detected)
}

const scanHash = (hash, components) => {
    for (const [component, entry] of Object.entries(components)) {
        const version = entry.extractors?.hashes?.[hash]
        if (version) {
            return [{ component, version, detection: 'hash' }]
        }
    }
    return []
}

// Numeric-aware version comparison, matching upstream exactly — including
// that a numeric segment sorts above a non-numeric one.
export const isAtOrAbove = (version1, version2) => {
    const v1 = String(version1).split(/[.-]/g)
    const v2 = String(version2).split(/[.-]/g)
    const length = Math.max(v1.length, v2.length)
    for (let i = 0; i < length; i++) {
        const a = toComparable(v1[i])
        const b = toComparable(v2[i])
        if (typeof a !== typeof b) {
            return typeof a === 'number'
        }
        if (a > b) {
            return true
        }
        if (a < b) {
            return false
        }
    }
    return true
}

const toComparable = (segment) => {
    if (segment === undefined) {
        return 0
    }
    return /^[0-9]+$/.test(segment) ? parseInt(segment, 10) : segment
}

// Attach the advisories that apply to each detected version.
const attachVulnerabilities = (detections, components) =>
    detections.map((detection) => {
        const entry = components[detection.component]
        const vulnerabilities = []
        for (const vuln of entry?.vulnerabilities || []) {
            if (vuln.below !== undefined && isAtOrAbove(detection.version, vuln.below)) {
                continue
            }
            if (
                vuln.atOrAbove !== undefined &&
                !isAtOrAbove(detection.version, vuln.atOrAbove)
            ) {
                continue
            }
            if (vuln.excludes?.includes(detection.version)) {
                continue
            }
            vulnerabilities.push(vuln)
        }
        return { ...detection, npmname: entry?.npmname, vulnerabilities }
    })

// Identify libraries in one file.
//
// Extractor precedence follows upstream: content patterns first, then the
// replacement patterns that handle minified code, then an exact file hash.
// Filename and URI are additive rather than a fallback — a bundle can name a
// vendored library it also inlines, and both are worth reporting.
//
// `sha1` is optional; without it the hash extractor is skipped, which only
// costs detection of byte-identical library distributions.
export const scanFile = ({ src, content, sha1 }, repository) => {
    const components = repository?.components
    if (!components) {
        return []
    }
    const detections = []

    if (typeof content === 'string' && content.length > 0) {
        const normalized = content.replace(/\r\n|\r/g, '\n')
        let byContent = scan(normalized, 'filecontent', components)
        if (byContent.length === 0) {
            byContent = scan(normalized, 'filecontentreplace', components)
        }
        if (byContent.length === 0 && sha1) {
            byContent = scanHash(sha1, components)
        }
        detections.push(...byContent)
    }

    if (src) {
        detections.push(...scan(src, 'filename', components))
        detections.push(...scan(src, 'uri', components))
    }

    return attachVulnerabilities(uniq(detections), components)
}

// The highest severity across a set of detections, or null if none are
// vulnerable. Order matches the severities Retire.js publishes.
const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical']

export const highestSeverity = (libraries) => {
    let best = null
    for (const library of libraries || []) {
        for (const vuln of library.vulnerabilities || []) {
            const rank = SEVERITY_ORDER.indexOf(vuln.severity)
            if (rank > SEVERITY_ORDER.indexOf(best)) {
                best = vuln.severity
            }
        }
    }
    return best
}
