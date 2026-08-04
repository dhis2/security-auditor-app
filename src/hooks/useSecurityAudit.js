import { useState, useCallback } from 'react'
import { useDataEngine } from '@dhis2/app-runtime'
import { runAudit } from '../audit/runAudit'

// Sort findings: failures first, then warnings, then errors, then passes.
// Within a status, higher `ranking` wins. Unknown statuses fall to the end
// rather than producing NaN comparisons.
const STATUS_ORDER = { fail: 0, warning: 1, error: 2, pass: 3, running: 4 }
const orderOf = (status) => STATUS_ORDER[status] ?? 99
const sortFindings = (findings) =>
    [...findings].sort((a, b) => {
        const statusDiff = orderOf(a.status) - orderOf(b.status)
        if (statusDiff !== 0) {
            return statusDiff
        }
        return (b.ranking || 0) - (a.ranking || 0)
    })

// React state binding around the pure runAudit() runner. The runner is fully
// testable without React; this hook only handles state updates and progress.
export const useSecurityAudit = (config = {}) => {
    const engine = useDataEngine()
    const [auditStatus, setAuditStatus] = useState('idle') // idle, running, completed, error
    const [findings, setFindings] = useState([])
    const [progress, setProgress] = useState({ current: 0, total: 0 })
    const [apiResponses, setApiResponses] = useState([])

    const runAuditCb = useCallback(
        async (overrideConfig) => {
            setAuditStatus('running')
            setFindings([])
            setApiResponses([])
            setProgress({ current: 0, total: 0 })

            const callbacks = {
                onStartRun: ({ total }) => setProgress({ current: 0, total }),
                onStart: (check) => {
                    setFindings((prev) => [
                        ...prev,
                        {
                            id: check.id,
                            title: check.title,
                            description: check.description,
                            ranking: check.ranking || 0,
                            status: 'running',
                            message: null,
                            details: null,
                        },
                    ])
                },
                onData: (check, data) => {
                    setApiResponses((prev) => [
                        ...prev,
                        { checkId: check.id, checkTitle: check.title, data },
                    ])
                },
                onResult: (check, result) => {
                    setFindings((prev) =>
                        sortFindings(
                            prev.map((finding) =>
                                finding.id === check.id
                                    ? {
                                          ...finding,
                                          status: result.status,
                                          message: result.message,
                                          details: result.details,
                                      }
                                    : finding
                            )
                        )
                    )
                },
                onError: (check, error, override) => {
                    setFindings((prev) =>
                        prev.map((finding) =>
                            finding.id === check.id
                                ? {
                                      ...finding,
                                      status: override?.status ?? 'error',
                                      message:
                                          override?.message ??
                                          `Error executing check: ${error.message}`,
                                      details: override?.details ?? null,
                                  }
                                : finding
                        )
                    )
                },
                onProgress: (p) => setProgress(p),
                onComplete: () => setAuditStatus('completed'),
            }

            try {
                await runAudit(engine, overrideConfig || config, callbacks)
            } catch (error) {
                setAuditStatus('error')
                console.error('Audit error:', error)
            }
        },
        [engine, config]
    )

    return {
        auditStatus,
        findings,
        progress,
        runAudit: runAuditCb,
        apiResponses,
    }
}
