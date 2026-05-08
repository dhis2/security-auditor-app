import { buildAuditContext, runAudit } from './runAudit'
import { __resetApiMeCache } from '../utils/instanceInfo'

const TEST_CONFIG = {
    minPasswordLength: 8,
    maxInactiveMonths: 3,
    maxPasswordAgeDays: 365,
    maxSuperUserRoles: 5,
    maxAuditPages: 5000,
    maxAppAuditConcurrency: 4,
}

beforeEach(() => {
    __resetApiMeCache()
    global.fetch = jest.fn().mockRejectedValue(new Error('not configured'))
})

// Build a mock engine where each call's response is determined by matching
// the resource on the query. Lets tests provide a small declarative table.
const makeRoutedEngine = (routes) => {
    return {
        query: jest.fn(async (queryObj) => {
            const out = {}
            for (const [key, q] of Object.entries(queryObj)) {
                const handler = routes[q.resource]
                if (!handler) {
                    throw Object.assign(new Error('not found'), {
                        details: { httpStatusCode: 404 },
                    })
                }
                out[key] = await Promise.resolve(handler(q.params))
            }
            return out
        }),
    }
}

// =============================================================================
// buildAuditContext
// =============================================================================

describe('buildAuditContext', () => {
    it('populates ctx from successful prefetch responses', async () => {
        const engine = makeRoutedEngine({
            'system/info': () => ({ version: '2.42.0', contextPath: '' }),
            userRoles: () => ({
                userRoles: [{ id: 'r1', name: 'Admin', authorities: ['ALL'] }],
            }),
            systemSettings: () => ({
                minPasswordLength: '8',
                credentialsExpires: '0',
                enforceVerifiedEmail: 'true',
                lockMultipleFailedLogins: 'false',
            }),
        })
        // /api/me fetch will fail in this test (no fetch mock for it),
        // exercising the failure-tolerant path.
        const ctx = await buildAuditContext(engine)

        expect(ctx.systemInfo).toEqual({ version: '2.42.0', contextPath: '' })
        expect(ctx.systemVersion).toEqual({ major: 42, raw: '2.42.0' })
        expect(ctx.privilegedRoles).toHaveLength(1)
        expect(ctx.systemSettings.minPasswordLength).toBe('8')
        expect(ctx.responseHeaders).toBeNull()
    })

    it('isolates failures: one failed prefetch does not break the others', async () => {
        const engine = {
            query: jest.fn((queryObj) => {
                const resource = Object.values(queryObj)[0].resource
                if (resource === 'userRoles') {
                    return Promise.reject(new Error('forbidden'))
                }
                if (resource === 'system/info') {
                    return Promise.resolve({
                        systemInfo: { version: '2.42.0', contextPath: '' },
                    })
                }
                return Promise.resolve({ settings: {} })
            }),
        }
        const ctx = await buildAuditContext(engine)
        expect(ctx.privilegedRoles).toBeNull()
        expect(ctx.systemVersion).toEqual({ major: 42, raw: '2.42.0' })
        expect(ctx.systemSettings).toEqual({})
    })

    it('captures Headers from a successful /api/me fetch', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            headers: new Map([['server', 'nginx/1.20']]),
        })
        const engine = makeRoutedEngine({
            'system/info': () => ({ version: '2.42.0', contextPath: '' }),
            userRoles: () => ({ userRoles: [] }),
            systemSettings: () => ({}),
        })
        const ctx = await buildAuditContext(engine)
        expect(ctx.responseHeaders.get('server')).toBe('nginx/1.20')
    })

    it('partitions privileged users by authority via a single shared fetch', async () => {
        const engine = makeRoutedEngine({
            'system/info': () => ({ version: '2.42.0', contextPath: '' }),
            userRoles: () => ({
                userRoles: [
                    { id: 'r1', name: 'Super', authorities: ['ALL'] },
                    {
                        id: 'r2',
                        name: 'Routes',
                        authorities: ['F_PUBLIC_ROUTE_ADD'],
                    },
                ],
            }),
            systemSettings: () => ({}),
            users: () => ({
                users: [
                    { id: 'u1', userRoles: [{ id: 'r1', name: 'Super' }] },
                    { id: 'u2', userRoles: [{ id: 'r2', name: 'Routes' }] },
                ],
                pager: { page: 1, pageCount: 1, total: 2 },
            }),
        })
        const ctx = await buildAuditContext(engine, TEST_CONFIG)
        expect(ctx.privilegedUsersByAuthority.ALL.map((u) => u.id)).toEqual([
            'u1',
        ])
        expect(
            ctx.privilegedUsersByAuthority.F_PUBLIC_ROUTE_ADD.map((u) => u.id)
        ).toEqual(['u2'])
        // Exactly one users-fetch (in addition to the 3 prefetch queries).
        const userQueries = engine.query.mock.calls.filter((c) =>
            Object.values(c[0])[0].resource === 'users' ||
            Object.values(c[0])[0].resource?.startsWith('users')
        )
        expect(userQueries.length).toBe(1)
    })

    it('honors config.maxAuditPages on the authority users fetch', async () => {
        const engine = {
            query: jest.fn(async (q) => {
                const resource = Object.values(q)[0].resource
                if (resource === 'system/info') {
                    return { systemInfo: { version: '2.42.0', contextPath: '' } }
                }
                if (resource === 'userRoles') {
                    return {
                        userRoles: {
                            userRoles: [
                                { id: 'r1', name: 'Super', authorities: ['ALL'] },
                            ],
                        },
                    }
                }
                if (resource === 'systemSettings') {
                    return { settings: {} }
                }
                if (resource === 'users') {
                    // Runaway pager
                    return {
                        __page: {
                            users: [],
                            pager: { page: 1, pageCount: 9999, total: 0 },
                        },
                    }
                }
                throw new Error(`unexpected ${resource}`)
            }),
        }
        const ctx = await buildAuditContext(engine, {
            ...TEST_CONFIG,
            maxAuditPages: 3,
        })
        // With a runaway pager and maxAuditPages=3, fetchAllPaged throws.
        // buildAuditContext catches the error → privilegedUsersByAuthority is null.
        expect(ctx.privilegedUsersByAuthority).toBeNull()
    })
})

// =============================================================================
// runAudit (orchestration)
// =============================================================================

describe('runAudit', () => {
    // Common setup: prefetch returns minimal-but-valid data so individual
    // checks don't all short-circuit on "data unavailable".
    const minimalEngine = () =>
        makeRoutedEngine({
            'system/info': () => ({ version: '2.42.0', contextPath: '' }),
            userRoles: () => ({ userRoles: [] }),
            systemSettings: () => ({
                minPasswordLength: '12',
                credentialsExpires: '90',
                enforceVerifiedEmail: 'true',
                lockMultipleFailedLogins: 'true',
            }),
            users: () => ({ users: [], pager: { page: 1, pageCount: 1, total: 0 } }),
            'configuration/corsWhitelist': () => [],
            me: () => ({ id: 'me' }),
        })

    it('invokes lifecycle callbacks in order', async () => {
        const events = []
        await runAudit(minimalEngine(), TEST_CONFIG, {
            onStartRun: ({ total }) => events.push(`startRun:${total}`),
            onContext: () => events.push('context'),
            onStart: (check) => events.push(`start:${check.id}`),
            onResult: (check, result) =>
                events.push(`result:${check.id}=${result.status}`),
            onError: (check) => events.push(`error:${check.id}`),
            onProgress: ({ current }) => events.push(`progress:${current}`),
            onComplete: () => events.push('complete'),
        })

        expect(events[0]).toMatch(/^startRun:\d+$/)
        expect(events[1]).toBe('context')
        expect(events[events.length - 1]).toBe('complete')
        // Each check should produce a start, then result, then progress
        const startsBeforeResults = events.findIndex((e) =>
            e.startsWith('result:')
        )
        const firstStart = events.findIndex((e) => e.startsWith('start:'))
        expect(firstStart).toBeGreaterThan(0)
        expect(firstStart).toBeLessThan(startsBeforeResults)
    })

    it('routes a fetch failure through onError with no override', async () => {
        const failingEngine = {
            query: jest.fn((q) => {
                const resource = Object.values(q)[0].resource
                if (resource === 'configuration/corsWhitelist') {
                    return Promise.reject(new Error('boom'))
                }
                // delegate to minimal
                return minimalEngine().query(q)
            }),
        }
        const errors = []
        await runAudit(failingEngine, TEST_CONFIG, {
            onError: (check, error, override) =>
                errors.push({ id: check.id, message: error.message, override }),
        })

        const corsWhitelistError = errors.find(
            (e) => e.id === 'cors-whitelist'
        )
        expect(corsWhitelistError).toBeDefined()
        expect(corsWhitelistError.message).toBe('boom')
        expect(corsWhitelistError.override).toBeNull()
    })

    it('runs all 21 checks', async () => {
        const seen = new Set()
        await runAudit(minimalEngine(), TEST_CONFIG, {
            onStart: (check) => seen.add(check.id),
        })
        expect(seen.size).toBe(21)
    })

    it('completes even when prefetch fully fails (degrades to "unavailable" findings)', async () => {
        const failingEngine = {
            query: jest.fn(() =>
                Promise.reject(new Error('total network failure'))
            ),
        }
        const results = []
        await runAudit(failingEngine, TEST_CONFIG, {
            onResult: (check, result) =>
                results.push({ id: check.id, status: result.status }),
            onError: (check) => results.push({ id: check.id, status: 'error' }),
        })

        // Settings/header/authority checks should each produce a "warning"
        // result via their unavailable-finding paths, not propagate as errors.
        const settingsResult = results.find(
            (r) => r.id === 'password-policy'
        )
        expect(settingsResult.status).toBe('warning')
        const hstsResult = results.find((r) => r.id === 'hsts-header')
        expect(hstsResult.status).toBe('warning')
        const authResult = results.find((r) => r.id === 'user-roles')
        expect(authResult.status).toBe('warning')
    })
})
