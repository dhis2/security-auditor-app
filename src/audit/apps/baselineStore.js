import i18n from '@dhis2/d2-i18n'
import '../../i18nConfig'

// dataStore persistence for the apps integrity baseline.
//
// Kept out of the React hook for the same reason runAppsAudit is: the
// interesting behaviour here is the update-then-create fallback, and that is
// the path every instance takes on its very first save. Testing it should not
// require rendering anything.
//
// Same namespace as the audit config, separate key — the two have different
// lifecycles and very different sizes, and saving config should never rewrite
// hashes.
const DATASTORE_NAMESPACE = 'security-auditor-app'
const DATASTORE_KEY = 'apps-baseline'

export const BASELINE_RESOURCE = `dataStore/${DATASTORE_NAMESPACE}/${DATASTORE_KEY}`

export const is404 = (err) =>
    err?.details?.httpStatusCode === 404 || /\b404\b/.test(err?.message || '')

// Read the stored baseline. A missing key is the normal state before the
// first save, so it resolves to null rather than throwing.
export const loadBaselineDocument = async (engine) => {
    try {
        const result = await engine.query({
            baseline: { resource: BASELINE_RESOURCE },
        })
        return { baseline: result.baseline || null }
    } catch (err) {
        if (is404(err)) {
            return { baseline: null }
        }
        return {
            baseline: null,
            error: err.message || i18n.t('Failed to load the integrity baseline'),
        }
    }
}

// Write the baseline, creating the dataStore key if it does not exist yet.
// DHIS2 answers 404 to an update against a key that was never created.
export const saveBaselineDocument = async (engine, document) => {
    const write = (type) =>
        engine.mutate({ resource: BASELINE_RESOURCE, type, data: document })
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
            error: err.message || i18n.t('Failed to save the integrity baseline'),
        }
    }
}
