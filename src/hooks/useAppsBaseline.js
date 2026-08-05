import { useCallback, useEffect, useState } from 'react'
import { useDataEngine } from '@dhis2/app-runtime'
import { buildBaseline } from '../audit/apps/appsBaseline'
import {
    loadBaselineDocument,
    saveBaselineDocument,
} from '../audit/apps/baselineStore'

// React state binding around the baseline store. The dataStore semantics
// (missing key, update-then-create) live in baselineStore.js so they can be
// tested without rendering; this hook only owns state.
//
// Saving is never automatic. A baseline that refreshed itself at the end of
// every run would record whatever it just found — including an attacker's
// code — and report "unchanged" from then on. Accepting the current state as
// trusted has to be a decision someone makes.
export const useAppsBaseline = () => {
    const engine = useDataEngine()
    const [baseline, setBaseline] = useState(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [saving, setSaving] = useState(false)

    const load = useCallback(async () => {
        setLoading(true)
        setError(null)
        const { baseline: loaded, error: loadError } =
            await loadBaselineDocument(engine)
        setBaseline(loaded)
        if (loadError) {
            setError(loadError)
        }
        setLoading(false)
        return loaded
    }, [engine])

    const save = useCallback(
        async (results, meta) => {
            setSaving(true)
            setError(null)
            const document = buildBaseline(results, baseline, meta)
            const result = await saveBaselineDocument(engine, document)
            if (result.success) {
                setBaseline(document)
            } else {
                setError(result.error)
            }
            setSaving(false)
            return result.success
                ? { success: true, baseline: document }
                : result
        },
        [engine, baseline]
    )

    useEffect(() => {
        load()
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    return {
        baseline,
        loading,
        saving,
        error,
        loadBaseline: load,
        saveBaseline: save,
    }
}
