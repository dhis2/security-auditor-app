import { useCallback, useState } from 'react'
import { useDataEngine } from '@dhis2/app-runtime'
import { runAppsAudit } from '../audit/apps/runAppsAudit'

// React state binding around runAppsAudit. Mirrors useSecurityAudit's shape:
// the runner is pure and testable without React; this hook only handles
// state updates and progress reporting.
export const useAppsAudit = (config = {}) => {
    const engine = useDataEngine()
    const [status, setStatus] = useState('idle') // idle, running, completed, error
    const [results, setResults] = useState([])
    const [progress, setProgress] = useState({ current: 0, total: 0 })
    const [currentAppKey, setCurrentAppKey] = useState(null)
    const [error, setError] = useState(null)

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
                onListFailed: (err) => {
                    setError(err.message || String(err))
                },
                onComplete: () => {
                    setCurrentAppKey(null)
                    setStatus('completed')
                },
            }

            try {
                await runAppsAudit(engine, overrideConfig || config, callbacks)
            } catch (err) {
                setStatus('error')
                setError(err.message || String(err))
            }
        },
        [engine, config]
    )

    return {
        status,
        results,
        progress,
        currentAppKey,
        error,
        runAppsAudit: runAuditCb,
    }
}
