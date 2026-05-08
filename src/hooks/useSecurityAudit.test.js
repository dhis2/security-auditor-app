import { getSecurityChecks } from '../audit/checks'

const TEST_CONFIG = {
    minPasswordLength: 8,
    maxInactiveMonths: 3,
    maxPasswordAgeDays: 365,
    maxSuperUserRoles: 5,
    maxAuditPages: 5000,
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

    it('warns when minPasswordLength is non-numeric (no false pass)', () => {
        const check = findCheck('password-policy')
        const result = check.evaluate(null, {
            systemSettings: { minPasswordLength: 'abc' },
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/non-numeric|not configured/)
    })

    it('warns when minPasswordLength is missing (no false pass)', () => {
        const check = findCheck('password-policy')
        const result = check.evaluate(null, { systemSettings: {} })
        expect(result.status).toBe('warning')
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

    it('warns when credentialsExpires is non-numeric (no false pass)', () => {
        const check = findCheck('password-expiry-policy')
        const result = check.evaluate(null, {
            systemSettings: { credentialsExpires: 'never' },
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/non-numeric|not configured/)
    })

    it('warns when credentialsExpires is missing (no false pass)', () => {
        const check = findCheck('password-expiry-policy')
        const result = check.evaluate(null, { systemSettings: {} })
        expect(result.status).toBe('warning')
    })
})

// =============================================================================
// header checks: shared response-headers prefetch (B2)
// =============================================================================

describe('hsts-header (max-age validation)', () => {
    const check = () => findCheck('hsts-header')

    it('reports header unavailable when prefetch failed', () => {
        const result = check().evaluate(null, { responseHeaders: null })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/Unable to check HSTS header/)
    })

    it('warns when the header is absent', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({}),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/not present/)
    })

    it('passes for max-age >= 1 year', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'strict-transport-security':
                    'max-age=31536000; includeSubDomains',
            }),
        })
        expect(result.status).toBe('pass')
    })

    it('warns for max-age between 1 day and 1 year (no false pass)', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'strict-transport-security': 'max-age=600000',
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/below the recommended 1 year/)
    })

    it('warns for max-age below 1 day (no false pass)', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'strict-transport-security': 'max-age=100',
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/too short/)
    })

    it('warns when max-age is missing entirely (no false pass)', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'strict-transport-security': 'includeSubDomains',
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/missing or invalid/)
    })

    it('rejects max-age with non-digit suffix (no false pass for "31536000abc")', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'strict-transport-security': 'max-age=31536000abc',
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/missing or invalid/)
    })

    it('warns when max-age is zero (effectively disabling HSTS)', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'strict-transport-security': 'max-age=0',
            }),
        })
        expect(result.status).toBe('warning')
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

describe('csp-header (directive parsing, not just substring matching)', () => {
    const check = () => findCheck('csp-header')

    it('passes for a strict policy with all expected directives', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy':
                    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            }),
        })
        expect(result.status).toBe('pass')
    })

    it('warns when object-src is unset', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy':
                    "script-src 'self'; base-uri 'self'; frame-ancestors 'none'",
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/object-src is unset/)
    })

    it('warns when base-uri is unset', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy':
                    "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/base-uri is unset/)
    })

    it('warns when frame-ancestors is unset (clickjacking protection)', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy':
                    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/frame-ancestors is unset/)
    })

    it('warns when frame-ancestors contains a broad source', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy':
                    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors *",
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/frame-ancestors contains a broad source/)
    })

    it('lowercases source values so case-mangled keywords are still flagged', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy':
                    "default-src 'self'; script-src 'self' 'UNSAFE-INLINE'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/unsafe-inline/)
    })

    it("notes 'strict-dynamic' in details when present", () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy':
                    "default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            }),
        })
        expect(result.status).toBe('pass')
        expect(result.details).toMatch(/strict-dynamic/)
    })

    it('warns for default-src * (no false pass)', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy': 'default-src *',
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/broad source/)
    })

    it('warns when script-src includes a broad source like http:', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy':
                    "default-src 'self'; script-src 'self' http:",
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/broad source/)
    })

    it("warns when 'unsafe-inline' is in script-src", () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy':
                    "default-src 'self'; script-src 'self' 'unsafe-inline'",
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/unsafe-inline/)
    })

    it("warns when 'unsafe-eval' is in script-src", () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy':
                    "default-src 'self'; script-src 'self' 'unsafe-eval'",
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/unsafe-eval/)
    })

    it('warns when neither default-src nor script-src is present', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy': "img-src 'self'",
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/no default-src or script-src/)
    })

    it('flags report-only mode separately', () => {
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy-report-only':
                    "default-src 'self'; script-src 'self'",
            }),
        })
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/report-only/)
    })

    it('prefers the more specific script-src over default-src', () => {
        // default-src has unsafe-inline but script-src is strict; the policy
        // is fine for scripts because script-src overrides default-src.
        const result = check().evaluate(null, {
            responseHeaders: headersWith({
                'content-security-policy':
                    "default-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            }),
        })
        expect(result.status).toBe('pass')
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

describe('maxAuditPages threshold flows through to pagination', () => {
    it('uses config.maxAuditPages as the page-cap when fetching never-logged-in users', async () => {
        // A "runaway" engine returns pageCount: 9999 forever. With maxPages=3,
        // fetchAllPaged should throw on the 4th iteration.
        const runawayEngine = {
            query: jest.fn(async () => ({
                __page: {
                    users: [{ id: 'u' }],
                    pager: { page: 1, pageCount: 9999, total: 0 },
                },
            })),
        }
        const tightConfig = { ...TEST_CONFIG, maxAuditPages: 3 }
        const check = getSecurityChecks(tightConfig).find(
            (c) => c.id === 'users-never-logged-in'
        )
        await expect(check.fetch(runawayEngine)).rejects.toThrow(
            /exceeded maxPages \(3\)/
        )
    })

    it('uses config.maxAuditPages when fetching authority holders', async () => {
        const runawayEngine = {
            query: jest.fn(async () => ({
                __page: {
                    users: [],
                    pager: { page: 1, pageCount: 9999, total: 0 },
                },
            })),
        }
        const tightConfig = { ...TEST_CONFIG, maxAuditPages: 2 }
        const check = getSecurityChecks(tightConfig).find(
            (c) => c.id === 'user-roles'
        )
        await expect(
            check.fetch(runawayEngine, {
                privilegedRoles: [{ id: 'r1', authorities: ['ALL'] }],
            })
        ).rejects.toThrow(/exceeded maxPages \(2\)/)
    })
})

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
