import i18n from '@dhis2/d2-i18n'
import '../../i18nConfig'
import { vulnerableLibraries } from './classifyFindings'
import { explainWarning, warningSeverity } from './explainFindings'
import { sinkLabel } from './externalEndpoints'

// Arrange an app's findings into severity sections, each holding groups
// labelled by what they are about.
//
// The previous layout listed library advisories under a bare component
// heading with the severity buried inline as "[high] —", then a separate run
// of code findings. A reader had to scan prose to work out how bad anything
// was, and the two kinds of finding did not sort together at all.
//
// Here severity is the outer structure and the subject is a label, so the
// worst thing about an app is the first thing on the page:
//
//   HIGH    moment.js 2.29.1     CVE-2022-24785 — … — fixed in 2.29.2
//   MEDIUM  lodash 4.17.21       CVE-2025-13465 — … — fixed in 4.17.23
//   INFO    ./assets/main-x.js   Minified code — …
//
// Library advisories and code findings share one scale, so an obfuscated
// bundle sorts alongside a high-severity CVE rather than in its own list.
//
// Pure and shared by the UI and the HTML report: the two must not drift, and
// the ordering rules are worth testing on their own.

// Highest first. `unexamined` is deliberately last and deliberately not a
// severity — it records what could not be looked at, which is the absence of
// a finding rather than a mild one.
export const SEVERITY_ORDER = [
    'critical',
    'high',
    'medium',
    'low',
    'info',
    'unexamined',
]

export const severityLabel = (severity) =>
    ({
        critical: () => i18n.t('CRITICAL'),
        high: () => i18n.t('HIGH'),
        medium: () => i18n.t('MEDIUM'),
        low: () => i18n.t('LOW'),
        info: () => i18n.t('INFO'),
        unexamined: () => i18n.t('NOT EXAMINED'),
    }[severity] || (() => i18n.t('UNKNOWN')))()

// Identical findings usually fire many times in one file — ExtJS trips the
// eval check five times over. Repeating a row and its explanation five times
// buries the point rather than making it, so they collapse into one with a
// count.
export const groupWarnings = (warnings) => {
    const groups = new Map()
    for (const warning of warnings || []) {
        const key = `${warning.kind}:${warning.value ?? ''}`
        const existing = groups.get(key)
        if (existing) {
            existing.count += 1
        } else {
            groups.set(key, { key, warning, count: 1 })
        }
    }
    return [...groups.values()]
}

// One line per advisory: the identifiers to look up, what it is, and the
// version that fixes it — which is the actionable part.
const vulnerabilityItem = (vuln) => {
    const ids =
        vuln.identifiers?.CVE?.join(', ') || vuln.identifiers?.githubID || null
    const summary = vuln.identifiers?.summary || null
    const fixed = vuln.below
        ? i18n.t('Fixed in {{version}}', { version: vuln.below })
        : null
    return {
        title: ids || summary || i18n.t('Known vulnerability'),
        detail: [ids ? summary : null, fixed].filter(Boolean).join(' — '),
    }
}

const warningItem = ({ warning, count }) => {
    const explained = explainWarning(warning)
    const suffix = count > 1 ? ` ${i18n.t('({{count}}x)', { count })}` : ''
    return {
        title: (explained ? explained.title : warning.kind) + suffix,
        detail: explained
            ? explained.detail
            : [warning.value].filter(Boolean).join(' '),
    }
}

// One line per external host. The literal form found in the file is shown
// alongside the normalized host, because the two can look very different —
// that is the entire point of normalizing — and a reader checking the finding
// needs the string that is actually in the bundle.
const endpointItem = (endpoint) => {
    const flags = [
        endpoint.reachable
            ? i18n.t('reachable from code that opens connections')
            : null,
        // Transport labels. Named with the scheme rather than described in
        // the abstract, so the reader can match the label to the string in
        // the bundle without guessing which URL it refers to.
        endpoint.cleartext
            ? i18n.t('unencrypted ({{schemes}})', {
                  schemes: endpoint.schemes
                      .filter((s) => s === 'http' || s === 'ws')
                      .join(', '),
              })
            : null,
        endpoint.nonStandard
            ? i18n.t('non-standard protocol ({{schemes}})', {
                  schemes: endpoint.schemes
                      .filter(
                          (s) => !['https', 'wss', 'http', 'ws'].includes(s)
                      )
                      .join(', '),
              })
            : null,
        endpoint.ip ? i18n.t('hardcoded IP address') : null,
        endpoint.punycode ? i18n.t('punycode (non-ASCII) name') : null,
    ].filter(Boolean)
    return {
        title: flags.length
            ? `${endpoint.host} — ${flags.join(', ')}`
            : endpoint.host,
        detail: [
            endpoint.samples?.[0],
            endpoint.count > 1
                ? i18n.t('{{count}} references', { count: endpoint.count })
                : null,
            endpoint.files?.length
                ? i18n.t('in {{files}}', { files: endpoint.files.join(', ') })
                : null,
        ]
            .filter(Boolean)
            .join(' — '),
    }
}

// Build the sections. Returns only sections that have something in them, so
// callers can render the result directly.
//
// `external` is the app-level external-endpoint summary. It is app-level
// rather than per-file because reachability is decided by correlating hosts
// with connection APIs across the app's chunks, which no single file knows.
export const buildFindingSections = (files, { external } = {}) => {
    const bySeverity = new Map()
    const add = (severity, subject, item) => {
        if (!bySeverity.has(severity)) {
            bySeverity.set(severity, new Map())
        }
        const groups = bySeverity.get(severity)
        if (!groups.has(subject)) {
            groups.set(subject, [])
        }
        groups.get(subject).push(item)
    }

    // Library advisories, de-duplicated across the app's chunks. Each
    // advisory lands in its own severity section, so one library can appear
    // under both HIGH and MEDIUM — which is accurate: those are different
    // vulnerabilities that happen to share a component.
    for (const library of vulnerableLibraries(files)) {
        const subject = `${library.component} ${library.version}`
        for (const vuln of library.vulnerabilities) {
            add(vuln.severity || 'medium', subject, vulnerabilityItem(vuln))
        }
    }

    // Hosts outside the instance. A host in the same file as a connection API
    // is a capability the administrator should know about; one that is not is
    // an observation, since a bundled documentation link or data blob cannot
    // send anything anywhere.
    for (const endpoint of external?.hosts || []) {
        add(
            endpoint.reachable ? 'medium' : 'info',
            i18n.t('External connections'),
            endpointItem(endpoint)
        )
    }
    // Name the APIs once, under the same subject. Which ones are present
    // decides whether a host above is a capability or a string, so the reader
    // should be able to see the evidence for that call.
    if (external?.hosts?.length && external.sinks?.length) {
        add(
            external.reachableCount > 0 ? 'medium' : 'info',
            i18n.t('External connections'),
            {
                title: i18n.t('Connection APIs present in this app'),
                detail: external.sinks.map(sinkLabel).join(', '),
            }
        )
    }

    for (const file of files || []) {
        if (file.incomplete) {
            add('unexamined', file.src, {
                title: file.error || file.skipped || i18n.t('Not examined'),
                detail: '',
            })
            continue
        }
        if (file.error || file.skipped) {
            // Dead ends and non-JavaScript responses: recorded, but they are
            // not the app's code and carry no severity.
            add('info', file.src, {
                title: file.error || file.skipped,
                detail: '',
            })
            continue
        }
        for (const group of groupWarnings(file.warnings)) {
            add(
                warningSeverity(group.warning.kind),
                file.src,
                warningItem(group)
            )
        }
    }

    return SEVERITY_ORDER.filter((severity) => bySeverity.has(severity)).map(
        (severity) => ({
            severity,
            label: severityLabel(severity),
            groups: [...bySeverity.get(severity).entries()].map(
                ([subject, items]) => ({ subject, items })
            ),
        })
    )
}
