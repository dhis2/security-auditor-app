import { getAnalyzer } from '../../utils/jsXRay'
import { compareEntry } from './appsBaseline'
import { resultStatus } from './classifyFindings'
import { fetchInstalledApps } from './fetchInstalledApps'
import { getRetireRepository } from './retireRepository'
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
//
// `options.baseline` is the integrity baseline document from a previous run.
// Reading and writing it is the caller's job — this runner only compares
// against what it is handed, and never writes. Accepting drift has to be an
// explicit human act, because a baseline refreshed automatically after a
// compromise would quietly bless the attacker's code.
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

    // The integrity baseline recorded by a previous run, if any. Supplied by
    // the caller (which owns dataStore access) so this runner stays pure.
    const baselineApps = options.baseline?.apps || {}

    const analyze = options.analyze || (await getAnalyzer())

    // Loaded once per run and shared by every app. A failure here must not
    // sink the audit: without it the AST analysis and the integrity baseline
    // still work, and the missing piece is reported rather than assumed
    // clean.
    let retireRepository = options.retireRepository
    if (retireRepository === undefined) {
        try {
            retireRepository = await getRetireRepository({
                stored: options.storedSignatures,
            })
        } catch (err) {
            retireRepository = null
            callbacks.onRetireUnavailable?.(err)
        }
    }
    // Signature sets go stale. Report the age so "no known vulnerabilities"
    // can be read with the right amount of confidence.
    callbacks.onRetireRepository?.(
        retireRepository
            ? {
                  retrievedAt: retireRepository.retrievedAt,
                  origin: retireRepository.origin,
              }
            : { unavailable: true }
    )

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
                    retireRepository,
                })
                const stored = baselineApps[app.key]
                const withIntegrity = {
                    ...result,
                    integrity: compareEntry(result, stored),
                    baselineEntry: stored || null,
                }
                const enriched = {
                    ...withIntegrity,
                    status: resultStatus(withIntegrity),
                }
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
