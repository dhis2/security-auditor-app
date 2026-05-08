import { fetchAllPaged } from '../utils/pagination'

// Read passwordLastUpdated, falling back to the legacy nested path used pre-v42.
export const getPasswordLastUpdated = (user) =>
    user?.passwordLastUpdated ?? user?.userCredentials?.passwordLastUpdated ?? null

// True if two ISO timestamps are within `toleranceMs` of each other.
export const timestampsRoughlyEqual = (a, b, toleranceMs = 60_000) => {
    if (!a || !b) {
        return false
    }
    const diff = Math.abs(new Date(a).getTime() - new Date(b).getTime())
    return Number.isFinite(diff) && diff <= toleranceMs
}

// Returns the raw value of a response header from the shared prefetch, or
// null if the prefetch failed entirely (CORS, network, etc.).
export const getSharedHeader = (ctx, name) =>
    ctx.responseHeaders ? ctx.responseHeaders.get(name) : null

// Build the "could not check this header — shared response unavailable" finding.
export const headerUnavailableFinding = (label) => ({
    status: 'warning',
    message: `Unable to check ${label} header`,
    details: 'The audit could not fetch response headers from this DHIS2 instance. This may be due to CORS restrictions or a network failure.',
})

// Used by settings checks when the bulk systemSettings prefetch failed.
export const settingsUnavailableFinding = (label) => ({
    status: 'warning',
    message: `Unable to check ${label}`,
    details: 'The audit could not fetch system settings from this DHIS2 instance. The user may lack permission to read systemSettings, or the server may be unreachable.',
})

// Fetch the users that hold a given authority via any of the prefetched roles.
// Returns { users } for the evaluator, or { unavailable: true } if the shared
// role list could not be obtained during prefetch.
export const fetchAuthorityHolders = async (engine, ctx, authority) => {
    if (!ctx.privilegedRoles) {
        return { unavailable: true, users: [] }
    }
    const matchingRoleIds = ctx.privilegedRoles
        .filter((role) => (role.authorities || []).includes(authority))
        .map((role) => role.id)
    if (matchingRoleIds.length === 0) {
        return { users: [] }
    }
    const users = await fetchAllPaged(engine, {
        resource: 'users',
        params: {
            fields: 'id,username,userRoles[id,name]',
            filter: `userRoles.id:in:[${matchingRoleIds.join(',')}]`,
        },
    })
    return { users }
}

// Build the shared finding for an authority check.
export const summarizeAuthorityHolders = ({
    data,
    ctx,
    authority,
    authorityLabel,
    contextLabel,
    maxAllowed,
}) => {
    if (data.unavailable) {
        return {
            status: 'warning',
            message: `Could not check ${authorityLabel} authority — privileged role data unavailable`,
            details: 'The audit could not pre-fetch the list of roles with privileged authorities. The instance may be unreachable, or the user may lack permission to read userRoles.',
        }
    }

    const matchingRoleIds = new Set(
        ctx.privilegedRoles
            .filter((role) => (role.authorities || []).includes(authority))
            .map((role) => role.id)
    )
    const usersWithAuthority = new Map()
    for (const user of data.users) {
        const matchedRoles = (user.userRoles || []).filter((role) =>
            matchingRoleIds.has(role.id)
        )
        if (matchedRoles.length === 0) {
            continue
        }
        usersWithAuthority.set(user.id, {
            username: user.username || user.id,
            roles: matchedRoles.map((role) => role.name).filter(Boolean),
        })
    }

    const total = usersWithAuthority.size
    const hasIssue = total > maxAllowed

    let details = null
    if (total > 0) {
        const usersList = Array.from(usersWithAuthority.values())
            .map((info) => `${info.username} (${info.roles.join(', ')})`)
            .join('; ')
        details = `Users with ${authorityLabel} authority: ${usersList}`
    }

    return {
        status: hasIssue ? 'warning' : 'pass',
        message: hasIssue
            ? `Found ${total} users with ${authorityLabel} authority. Consider limiting ${contextLabel} (max: ${maxAllowed}).`
            : total > 0
            ? `Users with ${authorityLabel} authority: ${total} (max: ${maxAllowed}).`
            : `No users with ${authorityLabel} authority found.`,
        details,
    }
}
