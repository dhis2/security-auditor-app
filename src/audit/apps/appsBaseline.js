import i18n from '@dhis2/d2-i18n'
// Side-effecting: turns off i18next's HTML-escaping of interpolated values.
// Without it the file paths named in a drift message render as
// ".&#x2F;assets&#x2F;main-X.js". React and the report exporter each escape at
// their own boundary. See src/i18nConfig.js.
import '../../i18nConfig'

// Integrity baseline for installed apps.
//
// The AST heuristics in classifyFindings can only ever say "this looks like
// code that might do something". They cannot say "this is not the code DHIS2
// shipped", because on a minified bundle there is nothing left to compare
// against. The baseline answers that second question directly: record what
// every app's files hashed to, then report what changed.
//
// The signal worth acting on is a content change with no version change. An
// app whose version moved was updated, which is expected and routine. An app
// whose bundle changed while it still claims the same version was modified in
// place — that is what tampering looks like, and it has no benign explanation
// on a server nobody has been editing by hand.
//
// Deliberately not stored: anything about the instance's data. The baseline
// holds app keys, versions, file paths and hashes.

export const BASELINE_VERSION = 1

export const INTEGRITY = {
    // Nothing recorded for this app yet — first sighting.
    NEW: 'new',
    // Same version, same hashes.
    UNCHANGED: 'unchanged',
    // Version moved. Expected after an upgrade or an App Hub install.
    UPDATED: 'updated',
    // Same version, different content. This is the one that matters.
    DRIFT: 'drift',
    // The app could not be hashed, so nothing can be concluded.
    UNKNOWN: 'unknown',
}

// Reduce a scan result's files to { src: hash }, skipping files that were
// never hashed (skipped, errored, or hashing unavailable).
export const fileHashes = (result) => {
    const out = {}
    for (const file of result?.files || []) {
        if (file.hash) {
            out[file.src] = file.hash
        }
    }
    return out
}

// Build the record we store for one app.
export const baselineEntry = (result) => ({
    version: result?.app?.version ?? null,
    name: result?.app?.name ?? null,
    files: fileHashes(result),
})

// Compare one scan result against its stored baseline entry.
//
// Returns { state, changed, added, removed } where the three arrays name the
// files responsible, so the report can say which file drifted rather than
// just that something did.
export const compareEntry = (result, stored) => {
    const current = fileHashes(result)
    const currentKeys = Object.keys(current)

    if (currentKeys.length === 0) {
        return { state: INTEGRITY.UNKNOWN, changed: [], added: [], removed: [] }
    }
    if (!stored || !stored.files) {
        return { state: INTEGRITY.NEW, changed: [], added: [], removed: [] }
    }

    const previous = stored.files
    const changed = currentKeys.filter(
        (src) => src in previous && previous[src] !== current[src]
    )
    const added = currentKeys.filter((src) => !(src in previous))
    const removed = Object.keys(previous).filter((src) => !(src in current))

    const versionMoved = (stored.version ?? null) !== (result?.app?.version ?? null)
    const differs = changed.length > 0 || added.length > 0 || removed.length > 0

    if (!differs) {
        // Unchanged content. A version string that moved on its own is odd
        // but not evidence of tampering, so it is still reported as updated.
        return {
            state: versionMoved ? INTEGRITY.UPDATED : INTEGRITY.UNCHANGED,
            changed,
            added,
            removed,
        }
    }
    return {
        state: versionMoved ? INTEGRITY.UPDATED : INTEGRITY.DRIFT,
        changed,
        added,
        removed,
    }
}

// Human-readable summary for the UI and the HTML report.
export const describeIntegrity = (integrity, stored) => {
    if (!integrity) {
        return null
    }
    const { state, changed, added, removed } = integrity
    const files = [...changed, ...added, ...removed]
    switch (state) {
        case INTEGRITY.DRIFT:
            return i18n.t(
                'Code changed while the version stayed at {{version}}. Changed: {{files}}',
                {
                    version: stored?.version || i18n.t('unknown'),
                    files: files.join(', '),
                }
            )
        case INTEGRITY.UPDATED:
            return i18n.t('Version changed from {{from}} — code differs as expected.', {
                from: stored?.version || i18n.t('unknown'),
            })
        case INTEGRITY.NEW:
            return i18n.t('No previous baseline for this app.')
        case INTEGRITY.UNKNOWN:
            return i18n.t('No files could be hashed, so integrity is unknown.')
        default:
            return i18n.t('Matches the recorded baseline.')
    }
}

// Build the document to persist from a completed run. Apps that could not be
// scanned keep whatever was previously recorded, so a transient fetch failure
// or an expired session does not erase a good baseline.
export const buildBaseline = (results, previous, meta = {}) => {
    const apps = { ...(previous?.apps || {}) }
    for (const result of results || []) {
        const key = result?.app?.key
        if (!key) {
            continue
        }
        const entry = baselineEntry(result)
        if (Object.keys(entry.files).length === 0) {
            continue
        }
        apps[key] = entry
    }
    return {
        baselineVersion: BASELINE_VERSION,
        recordedAt: meta.recordedAt || new Date().toISOString(),
        systemId: meta.systemId ?? previous?.systemId ?? null,
        dhis2Version: meta.dhis2Version ?? previous?.dhis2Version ?? null,
        apps,
    }
}
