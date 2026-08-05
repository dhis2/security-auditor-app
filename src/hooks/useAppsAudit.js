import { useCallback, useState } from 'react'
import { useDataEngine } from '@dhis2/app-runtime'
import { runAppsAudit } from '../audit/apps/runAppsAudit'
import { useAppsBaseline } from './useAppsBaseline'
import { useRetireSignatures } from './useRetireSignatures'
import { useInstanceInfo } from './useInstanceInfo'

// React state binding around runAppsAudit. Mirrors useSecurityAudit's shape:
// the runner is pure and testable without React; this hook only handles
// state updates and progress reporting.
export const useAppsAudit = (config = {}) => {
    const engine = useDataEngine()
    const { systemInfo } = useInstanceInfo()
    const {
        baseline,
        loadBaseline,
        saveBaseline,
        saving: savingBaseline,
        error: baselineError,
    } = useAppsBaseline()
    const {
        signatures,
        refreshing: refreshingSignatures,
        refreshError: signatureError,
        stale: signaturesStale,
        fetchSignatures,
        ensureFreshSignatures,
    } = useRetireSignatures(config.retireMaxAgeMinutes)
    const [status, setStatus] = useState('idle') // idle, running, completed, error
    const [results, setResults] = useState([])
    const [progress, setProgress] = useState({ current: 0, total: 0 })
    const [currentAppKey, setCurrentAppKey] = useState(null)
    const [error, setError] = useState(null)
    const [retireInfo, setRetireInfo] = useState(null)

    const runAuditCb = useCallback(
        async (overrideConfig) => {
            setStatus('running')
            setResults([])
            setProgress({ current: 0, total: 0 })
            setCurrentAppKey(null)
            setError(null)

            const callbacks = {
                onStartRun: ({ total }) => setProgress({ current: 0, total }),
                onAppStart: (app) => setCurrentAppKey(app.key),
                onAppDone: (app, result) => {
                    setResults((prev) => [...prev, result])
                },
                onAppError: (app, err) => {
                    setResults((prev) => [
                        ...prev,
                        {
                            app,
                            files: [],
                            error: err.message || String(err),
                            status: 'error',
                        },
                    ])
                },
                onProgress: (p) => setProgress(p),
                onRetireRepository: (info) => setRetireInfo(info),
                onListFailed: (err) => {
                    setError(err.message || String(err))
                },
                onComplete: () => {
                    setCurrentAppKey(null)
                    setStatus('completed')
                },
            }

            try {
                // Re-read the baseline at the start of each run rather than
                // trusting what was loaded on mount — another admin may have
                // accepted a new baseline in the meantime.
                // Refresh the vulnerability signatures first if they have
                // aged out. Falls back to whatever is already stored, and
                // ultimately to the copy vendored at build time, so a blocked
                // or offline network delays nothing.
                const freshSignatures = await ensureFreshSignatures()
                const current = await loadBaseline()
                await runAppsAudit(
                    engine,
                    overrideConfig || config,
                    callbacks,
                    {
                        contextPath: systemInfo?.contextPath,
                        baseline: current,
                        storedSignatures: freshSignatures,
                    }
                )
            } catch (err) {
                setStatus('error')
                setError(err.message || String(err))
            }
        },
        [
            engine,
            config,
            systemInfo?.contextPath,
            loadBaseline,
            ensureFreshSignatures,
        ]
    )

    const acceptBaseline = useCallback(
        () =>
            saveBaseline(results, {
                systemId: systemInfo?.systemId,
                dhis2Version: systemInfo?.version,
            }),
        [saveBaseline, results, systemInfo?.systemId, systemInfo?.version]
    )

    return {
        status,
        results,
        progress,
        currentAppKey,
        error,
        runAppsAudit: runAuditCb,
        retireInfo,
        signatures,
        signaturesStale,
        signatureError,
        refreshingSignatures,
        fetchSignatures,
        baseline,
        baselineError,
        savingBaseline,
        acceptBaseline,
    }
}
