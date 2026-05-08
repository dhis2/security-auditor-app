import { runAppsAudit } from './runAppsAudit'
import { __setAnalyzerForTests } from '../../utils/jsXRay'

const TEST_CONFIG = { maxAppAuditConcurrency: 4 }

const makeEngine = (apps) => ({
    query: jest.fn(async () => ({ apps })),
})

const makeFetchText = (filesByUrl) => async (url) => {
    if (!(url in filesByUrl)) {
        throw new Error(`HTTP 404 (no fixture for ${url})`)
    }
    return filesByUrl[url]
}

const cleanAnalyze = () => ({ warnings: [], isMinified: false })

afterEach(() => __setAnalyzerForTests(null))

describe('runAppsAudit', () => {
    it('lists apps via /api/apps and scans each one', async () => {
        const engine = makeEngine([
            {
                key: 'app-one',
                name: 'App One',
                baseUrl: 'https://server/dhis/api/apps/app-one',
            },
            {
                key: 'app-two',
                name: 'App Two',
                baseUrl: 'https://server/dhis/api/apps/app-two',
            },
        ])
        const fetchText = makeFetchText({
            'https://server/dhis/api/apps/app-one/index.html':
                '<script src="main.js"></script>',
            'https://server/dhis/api/apps/app-one/main.js': 'console.log(1)',
            'https://server/dhis/api/apps/app-two/index.html':
                '<script src="main.js"></script>',
            'https://server/dhis/api/apps/app-two/main.js': 'console.log(2)',
        })
        const results = await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText,
        })
        expect(results).toHaveLength(2)
        expect(results[0].app.key).toBe('app-one')
        expect(results[0].status).toBe('pass')
        expect(results[1].status).toBe('pass')
    })

    it('honors maxAppAuditConcurrency (no more than N in flight)', async () => {
        let active = 0
        let peak = 0
        const slowFetch = async (url) => {
            active += 1
            peak = Math.max(peak, active)
            await new Promise((r) => setTimeout(r, 5))
            active -= 1
            // Tiny index with no scripts so we only count the index.html fetch.
            return '<html></html>'
        }
        const engine = makeEngine(
            Array.from({ length: 8 }, (_, i) => ({
                key: `a${i}`,
                baseUrl: `api/apps/a${i}`,
            }))
        )
        await runAppsAudit(
            engine,
            { maxAppAuditConcurrency: 3 },
            {},
            { analyze: cleanAnalyze, fetchText: slowFetch }
        )
        expect(peak).toBeLessThanOrEqual(3)
    })

    it('reports status: fail when an app contains obfuscated code', async () => {
        const engine = makeEngine([
            { key: 'evil', baseUrl: 'https://server/dhis/api/apps/evil' },
        ])
        const fetchText = makeFetchText({
            'https://server/dhis/api/apps/evil/index.html':
                '<script src="main.js"></script>',
            'https://server/dhis/api/apps/evil/main.js': 'eval("...")',
        })
        const obfuscatedAnalyze = () => ({
            warnings: [{ kind: 'obfuscated-code', value: 'jsfuck' }],
        })
        const [result] = await runAppsAudit(
            engine,
            TEST_CONFIG,
            {},
            { analyze: obfuscatedAnalyze, fetchText }
        )
        expect(result.status).toBe('fail')
        expect(result.files[0].warnings[0].kind).toBe('obfuscated-code')
    })

    it('isolates per-app failures (one bad app does not abort the run)', async () => {
        const engine = makeEngine([
            { key: 'broken', baseUrl: 'https://server/dhis/api/apps/broken' },
            { key: 'ok', baseUrl: 'https://server/dhis/api/apps/ok' },
        ])
        const fetchText = async (url) => {
            if (url === 'https://server/dhis/api/apps/broken/index.html') {
                throw new Error('Network down')
            }
            return '<html></html>'
        }
        const results = await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText,
        })
        expect(results).toHaveLength(2)
        const broken = results.find((r) => r.app.key === 'broken')
        const ok = results.find((r) => r.app.key === 'ok')
        expect(broken.error).toMatch(/Network down/)
        expect(ok.status).toBe('pass')
    })

    it('emits the expected lifecycle callbacks', async () => {
        const events = []
        const engine = makeEngine([
            { key: 'a', baseUrl: 'https://server/dhis/api/apps/a' },
        ])
        const fetchText = makeFetchText({
            'https://server/dhis/api/apps/a/index.html': '<html></html>',
        })
        await runAppsAudit(
            engine,
            TEST_CONFIG,
            {
                onStartRun: ({ total }) => events.push(`startRun:${total}`),
                onAppStart: (app) => events.push(`appStart:${app.key}`),
                onAppDone: (app, result) =>
                    events.push(`appDone:${app.key}=${result.status}`),
                onProgress: ({ current, total }) =>
                    events.push(`progress:${current}/${total}`),
                onComplete: () => events.push('complete'),
            },
            { analyze: cleanAnalyze, fetchText }
        )
        expect(events).toEqual([
            'startRun:1',
            'appStart:a',
            'appDone:a=pass',
            'progress:1/1',
            'complete',
        ])
    })

    it('builds absolute paths via contextPath when app.baseUrl is missing', async () => {
        // Regression: previously the fallback used a relative URL
        // ("api/apps/<key>") which the browser resolved against the
        // security-auditor's own document URL, producing a 404 on any
        // instance mounted at a sub-path like /dhis. The fix is to use
        // the supplied contextPath to build an absolute path.
        const engine = makeEngine([
            // Note: no baseUrl on the app object.
            { key: 'no-base', name: 'No Base App' },
        ])
        const requested = []
        const fetchText = async (url) => {
            requested.push(url)
            return '<html></html>'
        }
        await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText,
            contextPath: '/dhis',
        })
        expect(requested).toContain('/dhis/api/apps/no-base/index.html')
    })

    it('handles a /api/apps fetch failure without throwing', async () => {
        const engine = {
            query: jest.fn(() => Promise.reject(new Error('forbidden'))),
        }
        const onListFailed = jest.fn()
        const onComplete = jest.fn()
        const results = await runAppsAudit(
            engine,
            TEST_CONFIG,
            { onListFailed, onComplete },
            { analyze: cleanAnalyze }
        )
        expect(results).toEqual([])
        expect(onListFailed).toHaveBeenCalledWith(expect.any(Error))
        expect(onComplete).toHaveBeenCalledWith([])
    })
})
