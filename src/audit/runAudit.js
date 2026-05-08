import { fetchApiMeHeaders } from '../utils/instanceInfo'
import { fetchAllPaged } from '../utils/pagination'
import { parseDhis2Version } from '../utils/version'
import {
    getSecurityChecks,
    PREFETCHED_SETTINGS_KEYS,
    PRIVILEGED_AUTHORITIES,
} from './checks'

// Pre-fetch shared data so dependent checks can reuse it. Each resource is
// captured independently so a failure in one doesn't cascade to unrelated
// checks. Returns a fully populated `ctx` (some fields may be null on failure).
export const buildAuditContext = async (engine, config = {}) => {
    const ctx = {
        systemVersion: null,
        systemInfo: null,
        privilegedRoles: null,
        privilegedUsersByAuthority: null,
        systemSettings: null,
        responseHeaders: null,
    }

    const [versionRes, rolesRes, settingsRes] = await Promise.allSettled([
        engine.query({
            systemInfo: {
                resource: 'system/info',
                params: { fields: 'version,contextPath' },
            },
        }),
        engine.query({
            userRoles: {
                resource: 'userRoles',
                params: {
                    fields: 'id,name,authorities',
                    paging: false,
                    filter: `authorities:in:[${PRIVILEGED_AUTHORITIES.join(',')}]`,
                },
            },
        }),
        engine.query({
            settings: {
                resource: 'systemSettings',
                params: { key: PREFETCHED_SETTINGS_KEYS },
            },
        }),
    ])
    if (versionRes.status === 'fulfilled') {
        ctx.systemInfo = versionRes.value.systemInfo || null
        ctx.systemVersion = parseDhis2Version(ctx.systemInfo?.version)
    }
    if (rolesRes.status === 'fulfilled') {
        ctx.privilegedRoles = rolesRes.value.userRoles?.userRoles || []
    }
    if (settingsRes.status === 'fulfilled') {
        ctx.systemSettings = settingsRes.value.settings || {}
    }

    // Single fetch for response-header checks; the same Promise is shared with
    // SystemInfo and the report exporter via fetchApiMeHeaders' cache.
    try {
        ctx.responseHeaders = await fetchApiMeHeaders(ctx.systemInfo?.contextPath)
    } catch {
        // Network or CORS failure — checks fall back to the "unavailable" finding.
    }

    // Single users-fetch covering ALL privileged role IDs, then partitioned
    // by authority in JS. Replaces 4 separate per-authority queries.
    if (ctx.privilegedRoles && ctx.privilegedRoles.length > 0) {
        const allRoleIds = ctx.privilegedRoles.map((r) => r.id)
        try {
            const users = await fetchAllPaged(
                engine,
                {
                    resource: 'users',
                    params: {
                        fields: 'id,username,userRoles[id,name]',
                        filter: `userRoles.id:in:[${allRoleIds.join(',')}]`,
                    },
                },
                config.maxAuditPages ? { maxPages: config.maxAuditPages } : undefined
            )
            const byAuthority = {}
            for (const authority of PRIVILEGED_AUTHORITIES) {
                const matchingRoleIds = new Set(
                    ctx.privilegedRoles
                        .filter((r) => (r.authorities || []).includes(authority))
                        .map((r) => r.id)
                )
                byAuthority[authority] = users.filter((u) =>
                    (u.userRoles || []).some((r) => matchingRoleIds.has(r.id))
                )
            }
            ctx.privilegedUsersByAuthority = byAuthority
        } catch {
            // Authority checks fall back to "unavailable".
        }
    } else if (ctx.privilegedRoles) {
        // No privileged roles defined → empty buckets.
        ctx.privilegedUsersByAuthority = Object.fromEntries(
            PRIVILEGED_AUTHORITIES.map((a) => [a, []])
        )
    }

    return ctx
}

// Resolve a check's data. Three modes:
//   - `check.fetch(engine, ctx)` for paged/multi-step fetches
//   - `check.query` for simple single-resource queries
//   - neither: the check consumes only the shared prefetch ctx
const resolveCheckData = async (check, engine, ctx) => {
    if (check.fetch) {
        return check.fetch(engine, ctx)
    }
    if (check.query) {
        return engine.query(check.query)
    }
    return null
}

// Run a single check, dispatching results through the supplied callbacks.
// Pure async — no React, no shared state — so easy to test.
const runOneCheck = async (check, engine, ctx, callbacks) => {
    callbacks.onStart?.(check)
    let data
    try {
        data = await resolveCheckData(check, engine, ctx)
    } catch (error) {
        const override = check.onError
            ? await Promise.resolve(check.onError(error))
            : null
        callbacks.onError?.(check, error, override)
        return
    }

    callbacks.onData?.(check, data)

    let result
    try {
        result = await Promise.resolve(check.evaluate(data, ctx))
    } catch (error) {
        callbacks.onError?.(check, error, null)
        return
    }

    callbacks.onResult?.(check, result)
}

// Run the full audit. `callbacks` lets a caller (e.g. the React hook) observe
// the progression: prefetch completion, per-check start/data/result/error, and
// overall completion. All callbacks are optional.
//
// Checks run in parallel after the shared prefetch completes. Most checks just
// read from ctx so the parallelism is essentially free; the few that issue
// their own fetches (the user-bucket checks) overlap their network roundtrips.
export const runAudit = async (engine, config, callbacks = {}) => {
    const checks = getSecurityChecks(config)
    const total = checks.length
    callbacks.onStartRun?.({ total })

    const ctx = await buildAuditContext(engine, config)
    callbacks.onContext?.(ctx)

    let completed = 0
    await Promise.all(
        checks.map(async (check) => {
            await runOneCheck(check, engine, ctx, callbacks)
            completed += 1
            callbacks.onProgress?.({ current: completed, total })
        })
    )

    callbacks.onComplete?.()
}
