import { useCallback, useEffect, useState } from 'react'
import { useDataEngine } from '@dhis2/app-runtime'
import {
    fetchLatestSignatures,
    isStale,
    loadStoredSignatures,
    saveStoredSignatures,
} from '../audit/apps/retireSignatures'

// React binding for the Retire.js signature set.
//
// Starting a scan refreshes them first if they are older than the configured
// window, and otherwise uses what is already stored — so the usual path is
// one button and the freshest data the network allows. An explicit Fetch
// button downloads unconditionally, for when the window is not the point.
//
// Every failure mode falls back rather than blocking. A download that fails
// leaves the previously stored set in place; if there is none, the copy
// vendored at build time is used. An audit that cannot reach github.com is
// still a useful audit — it just runs against older advisories, and says so.
//
// The dataStore read/write and the staleness rule live in
// audit/apps/retireSignatures.js so they can be tested without rendering.
export const useRetireSignatures = (maxAgeMinutes) => {
    const engine = useDataEngine()
    const [signatures, setSignatures] = useState(null)
    const [loading, setLoading] = useState(true)
    const [refreshing, setRefreshing] = useState(false)
    const [refreshError, setRefreshError] = useState(null)

    const load = useCallback(async () => {
        setLoading(true)
        const { signatures: stored } = await loadStoredSignatures(engine)
        setSignatures(stored)
        setLoading(false)
        return stored
    }, [engine])

    // Download unconditionally. Backs the explicit Fetch button, which is
    // available whether or not the current set is stale — an operator who
    // knows an advisory just landed should not have to wait out the window.
    const refresh = useCallback(async () => {
        setRefreshing(true)
        setRefreshError(null)
        try {
            const downloaded = await fetchLatestSignatures()
            setSignatures(downloaded)
            // A failed store is not a failed refresh: the downloaded set is
            // used for this session regardless, so a missing dataStore
            // authority costs persistence, not the check itself.
            const stored = await saveStoredSignatures(engine, downloaded)
            if (!stored.success) {
                setRefreshError(stored.error)
            }
            return { success: true, signatures: downloaded }
        } catch (err) {
            // Offline, blocked by CSP, proxied, rate-limited — all land here,
            // and all mean the same thing: carry on with what we have.
            const message = err.message || String(err)
            setRefreshError(message)
            return { success: false, error: message }
        } finally {
            setRefreshing(false)
        }
    }, [engine])

    // Called by the scan. Refreshes only if the stored set has aged out, and
    // returns the signature set to use — never throws, and never returns less
    // than we already had.
    const ensureFresh = useCallback(async () => {
        const current = await load()
        // 0 means never reach out on its own. The manual Fetch button is
        // unaffected — this governs what a scan does without being asked.
        if (maxAgeMinutes === 0) {
            return current
        }
        if (!isStale(current?.retrievedAt, maxAgeMinutes)) {
            setRefreshError(null)
            return current
        }
        const result = await refresh()
        return result.success ? result.signatures : current
    }, [load, refresh, maxAgeMinutes])

    useEffect(() => {
        load()
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    return {
        signatures,
        loading,
        refreshing,
        refreshError,
        // Recomputed on render rather than stored, so the UI reflects the
        // window lapsing without needing a timer.
        stale:
            maxAgeMinutes !== 0 &&
            isStale(signatures?.retrievedAt, maxAgeMinutes),
        fetchSignatures: refresh,
        ensureFreshSignatures: ensureFresh,
    }
}
