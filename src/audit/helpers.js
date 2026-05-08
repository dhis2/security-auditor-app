import i18n from '@dhis2/d2-i18n'

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
    message: i18n.t('Unable to check {{label}} header', { label }),
    details: i18n.t(
        'The audit could not fetch response headers from this DHIS2 instance. This may be due to CORS restrictions or a network failure.'
    ),
})

// Used by settings checks when the bulk systemSettings prefetch failed.
export const settingsUnavailableFinding = (label) => ({
    status: 'warning',
    message: i18n.t('Unable to check {{label}}', { label }),
    details: i18n.t(
        'The audit could not fetch system settings from this DHIS2 instance. The user may lack permission to read systemSettings, or the server may be unreachable.'
    ),
})

// Build the shared finding for an authority check. Reads from the prefetched
// users-by-authority map populated in buildAuditContext.
export const summarizeAuthorityHolders = ({
    ctx,
    authority,
    authorityLabel,
    contextLabel,
    maxAllowed,
}) => {
    if (!ctx.privilegedUsersByAuthority) {
        return {
            status: 'warning',
            message: i18n.t(
                'Could not check {{authority}} authority — privileged role data unavailable',
                { authority: authorityLabel }
            ),
            details: i18n.t(
                'The audit could not pre-fetch the list of roles with privileged authorities. The instance may be unreachable, or the user may lack permission to read userRoles.'
            ),
        }
    }

    const matchingRoleIds = new Set(
        ctx.privilegedRoles
            .filter((role) => (role.authorities || []).includes(authority))
            .map((role) => role.id)
    )
    const users = ctx.privilegedUsersByAuthority[authority] || []
    const usersWithAuthority = new Map()
    for (const user of users) {
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
        details = i18n.t('Users with {{authority}} authority: {{usersList}}', {
            authority: authorityLabel,
            usersList,
        })
    }

    let message
    if (hasIssue) {
        message = i18n.t(
            'Found {{total}} users with {{authority}} authority. Consider limiting {{context}} (max: {{max}}).',
            {
                total,
                authority: authorityLabel,
                context: contextLabel,
                max: maxAllowed,
            }
        )
    } else if (total > 0) {
        message = i18n.t(
            'Users with {{authority}} authority: {{total}} (max: {{max}}).',
            { authority: authorityLabel, total, max: maxAllowed }
        )
    } else {
        message = i18n.t('No users with {{authority}} authority found.', {
            authority: authorityLabel,
        })
    }

    return {
        status: hasIssue ? 'warning' : 'pass',
        message,
        details,
    }
}
