import { getSecurityChecks } from './useSecurityAudit'

const TEST_CONFIG = {
    minPasswordLength: 8,
    maxInactiveMonths: 3,
    maxPasswordAgeDays: 365,
    maxSuperUserRoles: 5,
}

const findCheck = (id) =>
    getSecurityChecks(TEST_CONFIG).find((c) => c.id === id)

// Minimal mock engine: returns the next response in `responses` for each call.
const makeEngine = (responses) => {
    let i = 0
    return {
        query: jest.fn(async () => {
            const next = responses[i++]
            if (next === undefined) {
                throw new Error(
                    `Mock engine: unexpected call ${i} (only ${responses.length} responses queued)`
                )
            }
            return next
        }),
    }
}

const headersWith = (entries) => ({
    get: (name) => entries[name.toLowerCase()] ?? null,
})

// =============================================================================
// Shared authority helper (covers all 4 authority checks via summariseAuthorityHolders)
// =============================================================================

describe('authority checks (user-roles, route-manager, impersonate, system-setting)', () => {
    it('returns "data unavailable" when ctx.privilegedRoles is null', () => {
        const check = findCheck('user-roles')
        const result = check.evaluate(
            { users: [], unavailable: true },
            { privilegedRoles: null }
        )
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/privileged role data unavailable/)
    })

    it('reports zero holders cleanly', () => {
        const check = findCheck('user-roles')
        const result = check.evaluate(
            { users: [] },
            { privilegedRoles: [] }
        )
        expect(result.status).toBe('pass')
        expect(result.message).toMatch(/No users with ALL authority/)
    })

    it('passes when count is at or below the configured maximum', () => {
        const check = findCheck('user-roles')
        const ctx = {
            privilegedRoles: [
                { id: 'r1', name: 'Superuser', authorities: ['ALL'] },
            ],
        }
        const data = {
            users: [
                { id: 'u1', username: 'alice', userRoles: [{ id: 'r1', name: 'Superuser' }] },
                { id: 'u2', username: 'bob', userRoles: [{ id: 'r1', name: 'Superuser' }] },
            ],
        }
        const result = check.evaluate(data, ctx)
        expect(result.status).toBe('pass')
        expect(result.details).toContain('alice')
        expect(result.details).toContain('bob')
    })

    it('warns when count exceeds maxSuperUserRoles', () => {
        const check = findCheck('user-roles')
        const ctx = {
            privilegedRoles: [
                { id: 'r1', name: 'Superuser', authorities: ['ALL'] },
            ],
        }
        const data = {
            users: Array.from({ length: 10 }, (_, i) => ({
                id: `u${i}`,
                username: `user${i}`,
                userRoles: [{ id: 'r1', name: 'Superuser' }],
            })),
        }
        const result = check.evaluate(data, ctx)
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/Found 10 users with ALL/)
    })

    it('route-manager-authority targets F_PUBLIC_ROUTE_ADD, not M_routemanager', () => {
        const check = findCheck('route-manager-authority')
        const ctx = {
            privilegedRoles: [
                { id: 'r1', name: 'Routes', authorities: ['F_PUBLIC_ROUTE_ADD'] },
                { id: 'r2', name: 'Old', authorities: ['M_routemanager'] },
            ],
        }
        const data = {
            users: [
                { id: 'u1', username: 'alice', userRoles: [{ id: 'r1', name: 'Routes' }] },
            ],
        }
        const result = check.evaluate(data, ctx)
        expect(result.status).toBe('pass')
        expect(result.details).toContain('alice')
    })
})

describe('fetchAuthorityHolders (the fetch side of authority checks)', () => {
    it('returns { unavailable: true } when prefetch failed', async () => {
        const check = findCheck('user-roles')
        const engine = makeEngine([])
        const result = await check.fetch(engine, { privilegedRoles: null })
        expect(result.unavailable).toBe(true)
        expect(engine.query).not.toHaveBeenCalled()
    })

    it('returns empty users when no role grants the authority', async () => {
        const check = findCheck('user-roles')
        const engine = makeEngine([])
        const result = await check.fetch(engine, {
            privilegedRoles: [
                { id: 'r1', authorities: ['F_SOME_OTHER_AUTH'] },
            ],
        })
        expect(result.users).toEqual([])
        expect(engine.query).not.toHaveBeenCalled()
    })

    it('issues a paged users query restricted to matching role IDs', async () => {
        const check = findCheck('user-roles')
        const engine = makeEngine([
            {
                __page: {
                    users: [{ id: 'u1', username: 'alice', userRoles: [{ id: 'r1' }] }],
                    pager: { page: 1, pageCount: 1, total: 1 },
                },
            },
        ])
        const result = await check.fetch(engine, {
            privilegedRoles: [
                { id: 'r1', authorities: ['ALL'] },
                { id: 'r2', authorities: ['ALL', 'F_OTHER'] },
            ],
        })
        expect(result.users).toHaveLength(1)
        const queryArg = engine.query.mock.calls[0][0].__page
        expect(queryArg.params.filter).toBe('userRoles.id:in:[r1,r2]')
    })
})

// =============================================================================
// settings checks: shared prefetch (B1) + key-absence handling (A3)
// =============================================================================

describe('email-verification (key-absence detection for v41 compat)', () => {
    const check = () => findCheck('email-verification')

    it('reports settings unavailable when prefetch failed', () => {
        const result = check().evaluate(null, { systemSettings: null })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/Unable to check email verification/)
    })

    it('reports "not available on this DHIS2 version" when key absent', () => {
        const result = check().evaluate(null, {
            systemSettings: { otherSetting: 'x' },
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/not available on this DHIS2 version/)
    })

    it('passes when enforceVerifiedEmail is "true"', () => {
        const result = check().evaluate(null, {
            systemSettings: { enforceVerifiedEmail: 'true' },
        })
        expect(result.status).toBe('pass')
    })

    it('warns when enforceVerifiedEmail is "false"', () => {
        const result = check().evaluate(null, {
            systemSettings: { enforceVerifiedEmail: 'false' },
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/not enforced/)
    })
})

describe('account-lockout (key-absence detection)', () => {
    const check = () => findCheck('account-lockout')

    it('reports "not available on this DHIS2 version" when key absent', () => {
        const result = check().evaluate(null, { systemSettings: {} })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/not available on this DHIS2 version/)
    })

    it('passes when lockMultipleFailedLogins is "true"', () => {
        const result = check().evaluate(null, {
            systemSettings: { lockMultipleFailedLogins: 'true' },
        })
        expect(result.status).toBe('pass')
    })
})

describe('password-policy (configurable threshold)', () => {
    it('warns when minPasswordLength is below the configured minimum', () => {
        const check = findCheck('password-policy')
        const result = check.evaluate(null, {
            systemSettings: { minPasswordLength: '4' },
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/4 characters/)
    })

    it('passes when minPasswordLength meets the configured minimum', () => {
        const check = findCheck('password-policy')
        const result = check.evaluate(null, {
            systemSettings: { minPasswordLength: '12' },
        })
        expect(result.status).toBe('pass')
    })
})

describe('password-expiry-policy', () => {
    it('warns when expiry is disabled (0)', () => {
        const check = findCheck('password-expiry-policy')
        const result = check.evaluate(null, {
            systemSettings: { credentialsExpires: '0' },
        })
        expect(result.status).toBe('warning')
    })

    it('passes when expiry is set', () => {
        const check = findCheck('password-expiry-policy')
        const result = check.evaluate(null, {
            systemSettings: { credentialsExpires: '90' },
        })
        expect(result.status).toBe('pass')
        expect(result.message).toMatch(/90 days/)
    })
})

// =============================================================================
// header checks: shared response-headers prefetch (B2)
// =============================================================================

describe('hsts-header', () => {
    const check = () => findCheck('hsts-header')

    it('reports header unavailable when prefetch failed', () => {
        const result = check().evaluate(null, { responseHeaders: null })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/Unable to check HSTS header/)
    })

    it('passes when the header is present', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'strict-transport-security': 'max-age=31536000',
            }),
        })
        expect(result.status).toBe('pass')
    })

    it('warns when the header is absent', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({}),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/not present/)
    })
})

describe('coop-header', () => {
    const check = () => findCheck('coop-header')

    it('passes for same-origin', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'cross-origin-opener-policy': 'same-origin',
            }),
        })
        expect(result.status).toBe('pass')
    })

    it('warns for unsafe-none', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'cross-origin-opener-policy': 'unsafe-none',
            }),
        })
        expect(result.status).toBe('warning')
    })

    it('warns for unexpected values', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'cross-origin-opener-policy': 'frobnicate',
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/unexpected value/)
    })
})

describe('cors-headers (dangerous-combination detection)', () => {
    const check = () => findCheck('cors-headers')

    it('FAILS for "*" with credentials true (the critical case)', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'access-control-allow-origin': '*',
                'access-control-allow-credentials': 'true',
            }),
        })
        expect(result.status).toBe('fail')
    })

    it('warns for "*" without credentials', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'access-control-allow-origin': '*',
            }),
        })
        expect(result.status).toBe('warning')
    })

    it('passes when no CORS headers are present', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({}),
        })
        expect(result.status).toBe('pass')
    })
})

// =============================================================================
// password-age (version-aware filter, two-query union)
// =============================================================================

describe('password-age fetch (version-aware filter)', () => {
    const filterFor = (call) => call[0].__page.params.filter

    it('uses the flat field on v42+', async () => {
        const check = findCheck('password-age')
        const engine = makeEngine([
            { __page: { users: [], pager: { page: 1, pageCount: 1, total: 0 } } },
            { __page: { users: [], pager: { page: 1, pageCount: 1, total: 0 } } },
        ])
        await check.fetch(engine, { systemVersion: { major: 42 } })
        const calls = engine.query.mock.calls
        expect(filterFor(calls[0])[1]).toMatch(/^passwordLastUpdated:lt:/)
        expect(filterFor(calls[1])[1]).toBe('passwordLastUpdated:null')
    })

    it('uses the nested userCredentials field on pre-v42', async () => {
        const check = findCheck('password-age')
        const engine = makeEngine([
            { __page: { users: [], pager: { page: 1, pageCount: 1, total: 0 } } },
            { __page: { users: [], pager: { page: 1, pageCount: 1, total: 0 } } },
        ])
        await check.fetch(engine, { systemVersion: { major: 41 } })
        const calls = engine.query.mock.calls
        expect(filterFor(calls[0])[1]).toMatch(
            /^userCredentials\.passwordLastUpdated:lt:/
        )
        expect(filterFor(calls[1])[1]).toBe(
            'userCredentials.passwordLastUpdated:null'
        )
    })

    it('unions stale + never-set users by id (no duplicates)', async () => {
        const check = findCheck('password-age')
        const engine = makeEngine([
            {
                __page: {
                    users: [
                        { id: 'u1', username: 'alice' },
                        { id: 'u2', username: 'bob' },
                    ],
                    pager: { page: 1, pageCount: 1, total: 2 },
                },
            },
            {
                __page: {
                    users: [
                        { id: 'u2', username: 'bob' }, // duplicate of u1's stale list
                        { id: 'u3', username: 'carol' },
                    ],
                    pager: { page: 1, pageCount: 1, total: 2 },
                },
            },
        ])
        const { users } = await check.fetch(engine, { systemVersion: { major: 42 } })
        expect(users).toHaveLength(3)
        expect(users.map((u) => u.id).sort()).toEqual(['u1', 'u2', 'u3'])
    })
})

// =============================================================================
// default-admin-password (A2 heuristic: empty OR matches `created`)
// =============================================================================

describe('default-admin-password (heuristic: never-set OR matches created)', () => {
    const check = () => findCheck('default-admin-password')

    it('passes when there is no admin user', () => {
        const result = check().evaluate({ adminUser: { users: [] } })
        expect(result.status).toBe('pass')
        expect(result.message).toMatch(/No admin user found/)
    })

    it('FAILS when passwordLastUpdated is empty', () => {
        const result = check().evaluate({
            adminUser: {
                users: [
                    {
                        username: 'admin',
                        created: '2026-01-01T00:00:00.000',
                        passwordLastUpdated: '',
                    },
                ],
            },
        })
        expect(result.status).toBe('fail')
    })

    it('FAILS when passwordLastUpdated equals `created` (within 60s)', () => {
        const result = check().evaluate({
            adminUser: {
                users: [
                    {
                        username: 'admin',
                        created: '2026-01-01T00:00:00.000',
                        passwordLastUpdated: '2026-01-01T00:00:30.000',
                    },
                ],
            },
        })
        expect(result.status).toBe('fail')
    })

    it('passes when passwordLastUpdated is clearly later than `created`', () => {
        const result = check().evaluate({
            adminUser: {
                users: [
                    {
                        username: 'admin',
                        created: '2026-01-01T00:00:00.000',
                        passwordLastUpdated: '2026-03-15T10:00:00.000',
                    },
                ],
            },
        })
        expect(result.status).toBe('pass')
    })

    it('reads passwordLastUpdated from legacy nested userCredentials (pre-v42)', () => {
        const result = check().evaluate({
            adminUser: {
                users: [
                    {
                        username: 'admin',
                        created: '2026-01-01T00:00:00.000',
                        userCredentials: {
                            passwordLastUpdated: '2026-03-15T10:00:00.000',
                        },
                    },
                ],
            },
        })
        expect(result.status).toBe('pass')
    })
})

// =============================================================================
// users-never-logged-in & users-inactive-3-months (server-side filters)
// =============================================================================

describe('users-never-logged-in', () => {
    it('issues a paged query filtered by lastLogin:null', async () => {
        const check = findCheck('users-never-logged-in')
        const engine = makeEngine([
            {
                __page: {
                    users: [{ id: 'u1', username: 'alice' }],
                    pager: { page: 1, pageCount: 1, total: 1 },
                },
            },
        ])
        await check.fetch(engine)
        const params = engine.query.mock.calls[0][0].__page.params
        expect(params.filter).toContain('lastLogin:null')
        expect(params.filter).toContain('disabled:eq:false')
    })

    it('warns when there are never-logged-in users', () => {
        const check = findCheck('users-never-logged-in')
        const result = check.evaluate({ users: [{ id: 'u1', username: 'alice' }] })
        expect(result.status).toBe('warning')
        expect(result.details).toContain('alice')
    })
})

describe('users-inactive-3-months', () => {
    it('passes inactiveMonths param and excludes never-logged-in users', async () => {
        const check = findCheck('users-inactive-3-months')
        const engine = makeEngine([
            {
                __page: {
                    users: [
                        { id: 'u1', username: 'alice', lastLogin: '2025-01-01' },
                        { id: 'u2', username: 'bob', lastLogin: null },
                    ],
                    pager: { page: 1, pageCount: 1, total: 2 },
                },
            },
        ])
        const { users } = await check.fetch(engine)
        const params = engine.query.mock.calls[0][0].__page.params
        expect(params.inactiveMonths).toBe(3)
        expect(users.map((u) => u.id)).toEqual(['u1'])
    })
})
