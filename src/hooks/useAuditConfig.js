import { useState, useEffect, useCallback } from 'react'
import { useDataEngine } from '@dhis2/app-runtime'

// Default configuration values
const DEFAULT_CONFIG = {
    minPasswordLength: 8,
    maxInactiveMonths: 3,
    maxPasswordAgeDays: 365,
    maxSuperUserRoles: 5,
}

// DataStore namespace for the app
const DATASTORE_NAMESPACE = 'security-auditor-app'
const DATASTORE_KEY = 'config'

export const useAuditConfig = () => {
    const engine = useDataEngine()
    const [config, setConfig] = useState(DEFAULT_CONFIG)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)

    // Save configuration to dataStore
    const saveConfig = useCallback(
        async (newConfig) => {
            setError(null)

            try {
                const mutation = {
                    resource: `dataStore/${DATASTORE_NAMESPACE}/${DATASTORE_KEY}`,
                    type: 'update',
                    data: newConfig,
                }

                await engine.mutate(mutation)
                setConfig(newConfig)
                return { success: true }
            } catch (err) {
                // If update fails because entry doesn't exist, try create
                if (err.message?.includes('404') || err.details?.httpStatusCode === 404) {
                    try {
                        const createMutation = {
                            resource: `dataStore/${DATASTORE_NAMESPACE}/${DATASTORE_KEY}`,
                            type: 'create',
                            data: newConfig,
                        }

                        await engine.mutate(createMutation)
                        setConfig(newConfig)
                        return { success: true }
                    } catch (createErr) {
                        const errorMsg = createErr.message || 'Failed to create configuration'
                        setError(errorMsg)
                        return { success: false, error: errorMsg }
                    }
                } else {
                    const errorMsg = err.message || 'Failed to save configuration'
                    setError(errorMsg)
                    return { success: false, error: errorMsg }
                }
            }
        },
        [engine]
    )

    // Load configuration from dataStore
    const loadConfig = useCallback(async () => {
        setLoading(true)
        setError(null)

        try {
            const query = {
                config: {
                    resource: `dataStore/${DATASTORE_NAMESPACE}/${DATASTORE_KEY}`,
                },
            }

            const result = await engine.query(query)
            const newConfig = { ...DEFAULT_CONFIG, ...result.config }
            setConfig(newConfig)
            return newConfig
        } catch (err) {
            // If dataStore entry doesn't exist (404), use defaults
            if (err.message?.includes('404') || err.details?.httpStatusCode === 404) {
                setConfig(DEFAULT_CONFIG)
                // Create the initial dataStore entry
                try {
                    const createMutation = {
                        resource: `dataStore/${DATASTORE_NAMESPACE}/${DATASTORE_KEY}`,
                        type: 'create',
                        data: DEFAULT_CONFIG,
                    }
                    await engine.mutate(createMutation)
                } catch (createErr) {
                    console.error('Error creating dataStore entry:', createErr)
                }
                return DEFAULT_CONFIG
            } else {
                setError(err.message || 'Failed to load configuration')
                console.error('Error loading config:', err)
                return DEFAULT_CONFIG
            }
        } finally {
            setLoading(false)
        }
    }, [engine])

    // Update a specific config value
    const updateConfigValue = useCallback(
        async (key, value) => {
            const newConfig = { ...config, [key]: value }
            return await saveConfig(newConfig)
        },
        [config, saveConfig]
    )

    // Reset to default configuration
    const resetConfig = useCallback(async () => {
        return await saveConfig(DEFAULT_CONFIG)
    }, [saveConfig])

    // Load config on mount
    useEffect(() => {
        loadConfig()
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    return {
        config,
        loading,
        error,
        saveConfig,
        updateConfigValue,
        resetConfig,
        reloadConfig: loadConfig,
    }
}
