import React, {
    createContext,
    useContext,
    useState,
    useEffect,
    useCallback,
} from 'react'
import { useDataEngine } from '@dhis2/app-runtime'

// Default configuration values. Exported so the import-config flow can merge
// older JSON exports (which may pre-date newer keys) with current defaults.
export const DEFAULT_CONFIG = {
    minPasswordLength: 8,
    maxInactiveMonths: 3,
    maxPasswordAgeDays: 365,
    maxSuperUserRoles: 5,
    maxAuditPages: 5000,
}

// DataStore namespace for the app
const DATASTORE_NAMESPACE = 'security-auditor-app'
const DATASTORE_KEY = 'config'

const RESOURCE = `dataStore/${DATASTORE_NAMESPACE}/${DATASTORE_KEY}`

const is404 = (err) =>
    err?.details?.httpStatusCode === 404 ||
    /\b404\b/.test(err?.message || '')

const AuditConfigContext = createContext(null)

// Single shared owner of the audit config. Place once near the app root so
// the hook can be consumed by both the audit runner and the configuration
// panel without each component owning an independent copy of the state.
export const AuditConfigProvider = ({ children }) => {
    const engine = useDataEngine()
    const [config, setConfig] = useState(DEFAULT_CONFIG)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)

    // Save the current config. If the entry doesn't exist yet (first save on
    // an instance that never had it), create it. This is the only path that
    // writes to the dataStore — `loadConfig` never writes.
    const saveConfig = useCallback(
        async (newConfig) => {
            setError(null)
            try {
                await engine.mutate({
                    resource: RESOURCE,
                    type: 'update',
                    data: newConfig,
                })
                setConfig(newConfig)
                return { success: true }
            } catch (err) {
                if (is404(err)) {
                    try {
                        await engine.mutate({
                            resource: RESOURCE,
                            type: 'create',
                            data: newConfig,
                        })
                        setConfig(newConfig)
                        return { success: true }
                    } catch (createErr) {
                        const message =
                            createErr.message || 'Failed to create configuration'
                        setError(message)
                        return { success: false, error: message }
                    }
                }
                const message = err.message || 'Failed to save configuration'
                setError(message)
                return { success: false, error: message }
            }
        },
        [engine]
    )

    // Load the config. On 404 we use the in-memory defaults — no write.
    // The dataStore entry is created lazily on the first explicit save.
    const loadConfig = useCallback(async () => {
        setLoading(true)
        setError(null)
        try {
            const result = await engine.query({
                config: { resource: RESOURCE },
            })
            const merged = { ...DEFAULT_CONFIG, ...result.config }
            setConfig(merged)
            return merged
        } catch (err) {
            if (is404(err)) {
                setConfig(DEFAULT_CONFIG)
                return DEFAULT_CONFIG
            }
            setError(err.message || 'Failed to load configuration')
            return DEFAULT_CONFIG
        } finally {
            setLoading(false)
        }
    }, [engine])

    const resetConfig = useCallback(
        () => saveConfig(DEFAULT_CONFIG),
        [saveConfig]
    )

    useEffect(() => {
        loadConfig()
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    const value = {
        config,
        loading,
        error,
        saveConfig,
        resetConfig,
        reloadConfig: loadConfig,
    }

    return (
        <AuditConfigContext.Provider value={value}>
            {children}
        </AuditConfigContext.Provider>
    )
}

export const useAuditConfig = () => {
    const ctx = useContext(AuditConfigContext)
    if (!ctx) {
        throw new Error(
            'useAuditConfig must be used inside an <AuditConfigProvider>'
        )
    }
    return ctx
}
