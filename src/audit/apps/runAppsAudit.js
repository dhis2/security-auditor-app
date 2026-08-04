import { getAnalyzer } from '../../utils/jsXRay'
import { resultStatus } from './classifyFindings'
import { fetchInstalledApps } from './fetchInstalledApps'
import { scanApp } from './scanApp'

// Run a configurable number of async tasks in parallel. Resolves after all
// tasks settle. Order of results matches input order.
const runWithConcurrency = async (items, concurrency, worker) => {
    const results = new Array(items.length)
    let cursor = 0
    const lanes = Array.from({ length: Math.max(1, concurrency) }, async () => {
        while (cursor < items.length) {
            const i = cursor++
            results[i] = await worker(items[i], i)
        }
    })
    await Promise.all(lanes)
    return results
}

// Run the full apps audit. `callbacks` mirrors runAudit's lifecycle hooks:
//   onStartRun({ total })
//   onAppStart(app)
//   onAppDone(app, result)
//   onAppError(app, error)
//   onProgress({ current, total })
//   onComplete(results)
//
// `options.fetchText`, `options.analyze`, and `options.contextPath` are
// test-injection seams. `contextPath` is the DHIS2 instance context path
// used to construct absolute URLs for app files (e.g. "/dhis"). When
// omitted, scanApp derives it from window.location.
export const runAppsAudit = async (engine, config = {}, callbacks = {}, options = {}) => {
    const concurrency = Math.max(1, config.maxAppAuditConcurrency || 4)

    let appsList
    try {
        appsList = await fetchInstalledApps(engine)
    } catch (error) {
        callbacks.onListFailed?.(error)
        callbacks.onComplete?.([])
        return []
    }

    callbacks.onStartRun?.({ total: appsList.length })

    const analyze = options.analyze || (await getAnalyzer())

    let completed = 0
    const results = await runWithConcurrency(
        appsList,
        concurrency,
        async (app) => {
            callbacks.onAppStart?.(app)
            try {
                const result = await scanApp({
                    app,
                    analyze,
                    fetchText: options.fetchText,
                    contextPath: options.contextPath,
                    config,
                })
                const enriched = { ...result, status: resultStatus(result) }
                callbacks.onAppDone?.(app, enriched)
                completed += 1
                callbacks.onProgress?.({
                    current: completed,
                    total: appsList.length,
                })
                return enriched
            } catch (error) {
                callbacks.onAppError?.(app, error)
                completed += 1
                callbacks.onProgress?.({
                    current: completed,
                    total: appsList.length,
                })
                return {
                    app,
                    files: [],
                    error: error.message || String(error),
                    status: 'error',
                }
            }
        }
    )

    callbacks.onComplete?.(results)
    return results
}
