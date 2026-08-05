import i18n from '@dhis2/d2-i18n'
import '../../i18nConfig'

// Fetching a fresh Retire.js signature set on demand, and remembering it.
//
// The app ships a vendored copy so the scan works with no internet at all.
// This is the opposite trade: an explicit, user-initiated refresh that trades
// one outbound request for current advisories.
//
// It is deliberately never automatic. Every other request the Apps Audit
// makes goes to the DHIS2 instance itself; this one goes to github.com, and
// the fact that an audit is being run is the sort of thing an operator should
// choose to disclose rather than have decided for them. Hence a button.
//
// The result is stored in the dataStore rather than in the browser, so a
// second administrator auditing the same instance gets current signatures
// without a second external request — which matters most on the restricted
// networks where only one machine can reach the internet at all.

const DATASTORE_NAMESPACE = 'security-auditor-app'
const DATASTORE_KEY = 'retire-signatures'

export const SIGNATURES_RESOURCE = `dataStore/${DATASTORE_NAMESPACE}/${DATASTORE_KEY}`

export const SIGNATURES_URL =
    'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v3.json'

// Extractor kinds this scanner can evaluate. `func` needs a running instance
// of the library and `ast` needs retire.js's own AST query engine, so both are
// dropped — they are also the bulk of the bytes, which matters for something
// we are about to write to the dataStore.
//
// Keep in step with USABLE_EXTRACTORS in scripts/update-retire-repository.js,
// which applies the same rule when refreshing the vendored copy.
const USABLE_EXTRACTORS = [
    'filename',
    'filecontent',
    'filecontentreplace',
    'uri',
    'hashes',
]

const stripUnusable = (advisories) => {
    const components = {}
    for (const [name, entry] of Object.entries(advisories || {})) {
        // Upstream ships a self-test entry that matches nothing real.
        if (name === 'retire-example') {
            continue
        }
        const extractors = {}
        for (const kind of USABLE_EXTRACTORS) {
            if (entry.extractors?.[kind]) {
                extractors[kind] = entry.extractors[kind]
            }
        }
        if (Object.keys(extractors).length === 0) {
            continue
        }
        components[name] = {
            ...(entry.npmname && { npmname: entry.npmname }),
            extractors,
            vulnerabilities: entry.vulnerabilities || [],
        }
    }
    return components
}

// Fetch the current signature set. `now` and `fetchImpl` are test seams.
export const fetchLatestSignatures = async ({
    fetchImpl = fetch,
    now = () => new Date(),
} = {}) => {
    const response = await fetchImpl(SIGNATURES_URL)
    if (!response.ok) {
        throw new Error(
            i18n.t('HTTP {{status}} fetching Retire.js signatures', {
                status: response.status,
            })
        )
    }
    const upstream = await response.json()
    const components = stripUnusable(upstream.advisories || upstream)
    if (Object.keys(components).length === 0) {
        // A CDN error page that happens to parse as JSON would otherwise be
        // stored as an empty signature set and quietly report everything as
        // clean.
        throw new Error(i18n.t('The downloaded signature data was not usable'))
    }
    return {
        source: SIGNATURES_URL,
        retrievedAt: now().toISOString(),
        components,
    }
}

const is404 = (err) =>
    err?.details?.httpStatusCode === 404 || /\b404\b/.test(err?.message || '')

export const loadStoredSignatures = async (engine) => {
    try {
        const result = await engine.query({
            signatures: { resource: SIGNATURES_RESOURCE },
        })
        return { signatures: result.signatures || null }
    } catch (err) {
        if (is404(err)) {
            return { signatures: null }
        }
        return {
            signatures: null,
            error: err.message || i18n.t('Failed to read stored signatures'),
        }
    }
}

export const saveStoredSignatures = async (engine, document) => {
    const write = (type) =>
        engine.mutate({ resource: SIGNATURES_RESOURCE, type, data: document })
    try {
        try {
            await write('update')
        } catch (err) {
            if (!is404(err)) {
                throw err
            }
            await write('create')
        }
        return { success: true }
    } catch (err) {
        return {
            success: false,
            error: err.message || i18n.t('Failed to store signatures'),
        }
    }
}

// Is a signature set old enough to be worth refreshing?
//
// Missing or unparseable timestamps count as stale: the point of the check is
// to decide whether to offer a refresh, and offering one is the safe answer
// when we cannot tell how old the data is.
export const isStale = (retrievedAt, maxAgeMinutes, now = Date.now()) => {
    if (!retrievedAt) {
        return true
    }
    const at = new Date(retrievedAt).getTime()
    if (Number.isNaN(at)) {
        return true
    }
    return now - at > maxAgeMinutes * 60 * 1000
}
