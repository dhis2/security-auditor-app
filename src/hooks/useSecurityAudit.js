import { useState, useCallback } from 'react'
import { useDataEngine } from '@dhis2/app-runtime'
import i18n from '@dhis2/d2-i18n'
import { fetchApiMeHeaders } from '../utils/instanceInfo'
import { fetchAllPaged } from '../utils/pagination'
import { parseDhis2Version, passwordLastUpdatedField } from '../utils/version'

// Read passwordLastUpdated, falling back to the legacy nested path used pre-v42.
const getPasswordLastUpdated = (user) =>
    user?.passwordLastUpdated ?? user?.userCredentials?.passwordLastUpdated ?? null

// True if two ISO timestamps are within `toleranceMs` of each other.
const timestampsRoughlyEqual = (a, b, toleranceMs = 60_000) => {
    if (!a || !b) {
        return false
    }
    const diff = Math.abs(new Date(a).getTime() - new Date(b).getTime())
    return Number.isFinite(diff) && diff <= toleranceMs
}

// systemSettings keys pre-fetched as a single batched request.
const PREFETCHED_SETTINGS_KEYS = [
    'minPasswordLength',
    'credentialsExpires',
    'enforceVerifiedEmail',
    'lockMultipleFailedLogins',
]

// Helper for header checks: returns the raw value from the shared prefetch
// or null if the prefetch failed entirely (CORS, network, etc.).
const getSharedHeader = (ctx, name) =>
    ctx.responseHeaders ? ctx.responseHeaders.get(name) : null

// Build the "could not check this header — shared response unavailable" finding.
const headerUnavailableFinding = (label) => ({
    status: 'warning',
    message: `Unable to check ${label} header`,
    details: 'The audit could not fetch response headers from this DHIS2 instance. This may be due to CORS restrictions or a network failure.',
})

// Used by settings checks when the bulk systemSettings prefetch failed.
const settingsUnavailableFinding = (label) => ({
    status: 'warning',
    message: `Unable to check ${label}`,
    details: 'The audit could not fetch system settings from this DHIS2 instance. The user may lack permission to read systemSettings, or the server may be unreachable.',
})

// Authorities pre-fetched as the audit's shared "privileged roles" set.
const PRIVILEGED_AUTHORITIES = [
    'ALL',
    'F_PUBLIC_ROUTE_ADD',
    'F_IMPERSONATE_USER',
    'F_SYSTEM_SETTING',
]

// Fetch the users that hold a given authority via any of the prefetched roles.
// Returns { users } for the evaluator, or { unavailable: true } if the shared
// role list could not be obtained during prefetch.
const fetchAuthorityHolders = async (engine, ctx, authority) => {
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
const summarizeAuthorityHolders = ({
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

// Security check definitions (config will be passed in)
const getSecurityChecks = (config) => [
    {
        id: 'user-roles',
        title: i18n.t('Users With ALL Authority'),
        description: i18n.t('Checking for users with administrative privileges'),
        ranking: 0,
        fetch: (engine, ctx) => fetchAuthorityHolders(engine, ctx, 'ALL'),
        evaluate: (data, ctx) =>
            summarizeAuthorityHolders({
                data,
                ctx,
                authority: 'ALL',
                authorityLabel: 'ALL',
                contextLabel: 'super user access',
                maxAllowed: config.maxSuperUserRoles || 5,
            }),
    },
    {
        id: 'route-manager-authority',
        title: i18n.t('Users Who Can Add Public Routes'),
        description: i18n.t('Checking for users with route creation privileges'),
        ranking: 0,
        fetch: (engine, ctx) => fetchAuthorityHolders(engine, ctx, 'F_PUBLIC_ROUTE_ADD'),
        evaluate: (data, ctx) =>
            summarizeAuthorityHolders({
                data,
                ctx,
                authority: 'F_PUBLIC_ROUTE_ADD',
                authorityLabel: 'F_PUBLIC_ROUTE_ADD',
                contextLabel: 'public route creation access',
                maxAllowed: config.maxSuperUserRoles || 5,
            }),
    },
    {
        id: 'impersonate-user-authority',
        title: i18n.t('Users Who Can Impersonate Others'),
        description: i18n.t('Checking for users with impersonation privileges'),
        ranking: 0,
        fetch: (engine, ctx) => fetchAuthorityHolders(engine, ctx, 'F_IMPERSONATE_USER'),
        evaluate: (data, ctx) =>
            summarizeAuthorityHolders({
                data,
                ctx,
                authority: 'F_IMPERSONATE_USER',
                authorityLabel: 'F_IMPERSONATE_USER',
                contextLabel: 'impersonation access',
                maxAllowed: 5,
            }),
    },
    {
        id: 'system-setting-authority',
        title: i18n.t('Users Who Can Change System Settings'),
        description: i18n.t('Checking for users with system settings modification privileges'),
        ranking: 0,
        fetch: (engine, ctx) => fetchAuthorityHolders(engine, ctx, 'F_SYSTEM_SETTING'),
        evaluate: (data, ctx) =>
            summarizeAuthorityHolders({
                data,
                ctx,
                authority: 'F_SYSTEM_SETTING',
                authorityLabel: 'F_SYSTEM_SETTING',
                contextLabel: 'system settings access',
                maxAllowed: 5,
            }),
    },
    {
        id: 'cors-whitelist',
        title: i18n.t('CORS Whitelist Configuration'),
        description: i18n.t('Checking CORS whitelist configuration'),
        ranking: 0,
        query: {
            corsWhitelist: {
                resource: 'configuration/corsWhitelist',
            },
        },
        evaluate: (data) => {
            const whitelistData = data.corsWhitelist
            const whitelist = Array.isArray(whitelistData)
                ? whitelistData
                : whitelistData && typeof whitelistData === 'string'
                ? whitelistData.split(',').map((s) => s.trim()).filter(Boolean)
                : []

            const hasWildcard = whitelist.some((url) => url.includes('*'))

            return {
                status: hasWildcard
                    ? 'fail'
                    : whitelist.length > 0
                    ? 'warning'
                    : 'pass',
                message: hasWildcard
                    ? 'CORS whitelist contains wildcards - security risk!'
                    : whitelist.length > 0
                    ? `CORS whitelist is configured with ${whitelist.length} allowed origins`
                    : 'CORS whitelist is empty',
                details:
                    hasWildcard || whitelist.length > 0
                        ? whitelist.join(', ')
                        : null,
            }
        },
    },
    {
        id: 'users-never-logged-in',
        title: i18n.t('Users Never Logged In'),
        description: i18n.t('Checking for active accounts that have never been used'),
        ranking: 0,
        fetch: async (engine) => {
            const users = await fetchAllPaged(engine, {
                resource: 'users',
                params: {
                    fields: 'id,username',
                    filter: ['disabled:eq:false', 'lastLogin:null'],
                },
            })
            return { users }
        },
        evaluate: (data) => {
            const users = data.users
            const total = users.length
            return {
                status: total > 0 ? 'warning' : 'pass',
                message: total > 0
                    ? `Found ${total} active accounts that have never logged in`
                    : 'All active users have logged in at least once',
                details: total > 0
                    ? `Consider removing unused accounts: ${users.slice(0, 5).map((u) => u.username).join(', ')}${total > 5 ? ` and ${total - 5} more` : ''}`
                    : null,
            }
        },
    },
    {
        id: 'users-inactive-3-months',
        title: i18n.t('Inactive User Accounts'),
        description: i18n.t('Checking for accounts with no recent activity'),
        ranking: 0,
        fetch: async (engine) => {
            const months = config.maxInactiveMonths || 3
            const users = await fetchAllPaged(engine, {
                resource: 'users',
                params: {
                    fields: 'id,username,lastLogin',
                    filter: 'disabled:eq:false',
                    inactiveMonths: months,
                },
            })
            // The inactiveMonths parameter on some DHIS2 versions also matches
            // users with a null lastLogin; exclude them — they're surfaced by
            // the dedicated "users never logged in" check.
            return { users: users.filter((u) => u.lastLogin) }
        },
        evaluate: (data) => {
            const maxMonths = config.maxInactiveMonths || 3
            const users = data.users
            const total = users.length
            return {
                status: total > 0 ? 'warning' : 'pass',
                message: total > 0
                    ? `Found ${total} users who haven't logged in for ${maxMonths}+ months`
                    : `All users with login history have recent activity (within ${maxMonths} months)`,
                details: total > 0
                    ? `Consider disabling inactive accounts: ${users.slice(0, 5).map((u) => u.username).join(', ')}${total > 5 ? ` and ${total - 5} more` : ''}`
                    : null,
            }
        },
    },
    {
        id: 'password-age',
        title: i18n.t('Password Age Verification'),
        description: i18n.t('Checking for stale or unchanged passwords'),
        ranking: 0,
        fetch: async (engine, ctx) => {
            const maxAgeDays = config.maxPasswordAgeDays || 365
            const thresholdDate = new Date()
            thresholdDate.setDate(thresholdDate.getDate() - maxAgeDays)
            const thresholdIso = thresholdDate.toISOString().slice(0, 10)
            const pwField = passwordLastUpdatedField(ctx.systemVersion)

            const [stale, neverSet] = await Promise.all([
                fetchAllPaged(engine, {
                    resource: 'users',
                    params: {
                        fields: 'id,username',
                        filter: [
                            'disabled:eq:false',
                            `${pwField}:lt:${thresholdIso}`,
                        ],
                    },
                }),
                fetchAllPaged(engine, {
                    resource: 'users',
                    params: {
                        fields: 'id,username',
                        filter: ['disabled:eq:false', `${pwField}:null`],
                    },
                }),
            ])

            // Server-side `:lt:` excludes nulls, so we union the two result
            // sets to include both "never set" and "older than threshold".
            const byId = new Map()
            for (const u of stale) {
                byId.set(u.id, u)
            }
            for (const u of neverSet) {
                byId.set(u.id, u)
            }
            return { users: Array.from(byId.values()) }
        },
        evaluate: (data) => {
            const maxAgeDays = config.maxPasswordAgeDays || 365
            const users = data.users
            const total = users.length
            return {
                status: total > 0 ? 'warning' : 'pass',
                message: total > 0
                    ? `Found ${total} users with passwords older than ${maxAgeDays} days or never changed`
                    : `All user passwords are up to date (within ${maxAgeDays} days)`,
                details: total > 0
                    ? `Users with stale passwords: ${users.slice(0, 5).map((u) => u.username).join(', ')}${total > 5 ? ` and ${total - 5} more` : ''}`
                    : null,
            }
        },
    },
    {
        id: 'password-policy',
        title: i18n.t('Password Policy Configuration'),
        description: i18n.t('Verifying minimum password length requirements'),
        ranking: 0,
        evaluate: (_data, ctx) => {
            if (!ctx.systemSettings) {
                return settingsUnavailableFinding('minimum password length')
            }
            const minPasswordLength = parseInt(
                ctx.systemSettings?.minPasswordLength || 0,
                10
            )
            const requiredLength = config.minPasswordLength || 8
            const hasIssue = minPasswordLength < requiredLength

            return {
                status: hasIssue ? 'warning' : 'pass',
                message: hasIssue
                    ? `Minimum password length is ${minPasswordLength} characters - should be at least ${requiredLength}`
                    : `Minimum password length is properly configured (${minPasswordLength} characters, required: ${requiredLength})`,
                details: hasIssue
                    ? `Weak passwords increase the risk of unauthorized access. Set minPasswordLength to at least ${requiredLength}.`
                    : null,
            }
        },
    },
    {
        id: 'password-expiry-policy',
        title: i18n.t('Password Expiry Policy'),
        description: i18n.t('Checking if forced password changes are enabled'),
        ranking: 0,
        evaluate: (_data, ctx) => {
            if (!ctx.systemSettings) {
                return settingsUnavailableFinding('password expiry policy')
            }
            const credentialsExpires =
                ctx.systemSettings?.credentialsExpires || '0'
            const expiryDays = parseInt(credentialsExpires, 10)
            const hasIssue = expiryDays === 0

            return {
                status: hasIssue ? 'warning' : 'pass',
                message: hasIssue
                    ? 'Password expiry is disabled - users never required to change passwords'
                    : `Password expiry is enabled (passwords expire after ${expiryDays} days)`,
                details: hasIssue
                    ? 'Consider enabling password expiry to force periodic password changes and reduce the risk of compromised credentials.'
                    : null,
            }
        },
    },
    {
        id: 'email-verification',
        title: i18n.t('Email Verification Enforcement'),
        description: i18n.t('Checking if email verification is enforced'),
        ranking: 0,
        evaluate: (_data, ctx) => {
            const settings = ctx.systemSettings
            if (!settings) {
                return settingsUnavailableFinding('email verification')
            }
            // The `enforceVerifiedEmail` setting was introduced in DHIS2 v42.
            // When the prefetch succeeded but the key is absent, the running
            // server doesn't support the setting.
            if (!('enforceVerifiedEmail' in settings)) {
                return {
                    status: 'warning',
                    message: 'Email verification setting not available on this DHIS2 version',
                    details: 'The enforceVerifiedEmail setting was introduced in DHIS2 v42. Upgrade to enable enforcement of verified email addresses.',
                }
            }
            const enforceVerifiedEmail =
                settings?.enforceVerifiedEmail === 'true'
            const hasIssue = !enforceVerifiedEmail

            return {
                status: hasIssue ? 'warning' : 'pass',
                message: hasIssue
                    ? 'Email verification is not enforced'
                    : 'Email verification is enforced',
                details: hasIssue
                    ? 'Consider enabling email verification to ensure user accounts are associated with valid email addresses.'
                    : null,
            }
        },
    },
    {
        id: 'https-connection',
        title: i18n.t('HTTPS Connection Security'),
        description: i18n.t('Verifying secure connection to the server'),
        ranking: 0,
        query: {
            // Dummy query to trigger the check
            me: {
                resource: 'me',
                params: {
                    fields: 'id',
                },
            },
        },
        evaluate: (data) => {
            const isHttps = window.location.protocol === 'https:'
            const hasIssue = !isHttps

            return {
                status: hasIssue ? 'fail' : 'pass',
                message: hasIssue
                    ? `Connection is using insecure HTTP protocol`
                    : 'Connection is secured with HTTPS',
                details: hasIssue
                    ? `Current protocol: ${window.location.protocol}. HTTPS should be used to encrypt data in transit and prevent man-in-the-middle attacks.`
                    : null,
            }
        },
    },
    {
        id: 'default-admin-password',
        title: i18n.t('Default Admin Password Check'),
        description: i18n.t('Checking if admin account uses default password'),
        ranking: 10,
        query: {
            adminUser: {
                resource: 'users',
                params: {
                    fields: 'id,username,created,passwordLastUpdated,userCredentials[passwordLastUpdated]',
                    filter: 'username:eq:admin',
                },
            },
        },
        evaluate: (data) => {
            const users = data.adminUser?.users || []
            if (users.length === 0) {
                return {
                    status: 'pass',
                    message: 'No admin user found',
                    details: null,
                }
            }

            const adminUser = users[0]
            const passwordLastUpdated = getPasswordLastUpdated(adminUser)
            const created = adminUser.created

            // The DHIS2 API populates `passwordLastUpdated` at user creation,
            // so an empty value alone is not a reliable signal. We additionally
            // flag the case where it matches `created` (within 60s), which
            // indicates the password has not been changed since the user was created.
            const neverSet = !passwordLastUpdated
            const matchesCreated = timestampsRoughlyEqual(passwordLastUpdated, created)
            const hasDefaultPassword = neverSet || matchesCreated

            return {
                status: hasDefaultPassword ? 'fail' : 'pass',
                message: hasDefaultPassword
                    ? 'Admin account password has not been changed since the account was created'
                    : 'Admin password has been changed',
                details: hasDefaultPassword
                    ? 'CRITICAL: The admin account password appears to be unchanged since user creation. If it is still the default ("district"), change it immediately to prevent unauthorized access.'
                    : null,
            }
        },
    },
    {
        id: 'account-lockout',
        title: i18n.t('Account Lockout Policy'),
        description: i18n.t('Checking if account lockout after failed login attempts is enabled'),
        ranking: 0,
        evaluate: (_data, ctx) => {
            const settings = ctx.systemSettings
            if (!settings) {
                return settingsUnavailableFinding('account lockout policy')
            }
            // Older DHIS2 versions don't expose `lockMultipleFailedLogins`
            // via /api/systemSettings; absence from the prefetched response
            // means the setting can't be inspected on this server.
            if (!('lockMultipleFailedLogins' in settings)) {
                return {
                    status: 'warning',
                    message: 'Account lockout setting not available on this DHIS2 version',
                    details: 'The lockMultipleFailedLogins setting is not exposed via the API on this DHIS2 version. Upgrade to enable automated lockout after failed login attempts.',
                }
            }
            const lockMultipleFailedLogins =
                settings?.lockMultipleFailedLogins === 'true'
            const hasIssue = !lockMultipleFailedLogins

            return {
                status: hasIssue ? 'warning' : 'pass',
                message: hasIssue
                    ? 'Account lockout after failed login attempts is disabled'
                    : 'Account lockout after failed login attempts is enabled',
                details: hasIssue
                    ? 'Consider enabling account lockout to prevent brute force password attacks.'
                    : null,
            }
        },
    },
    {
        id: 'hsts-header',
        title: i18n.t('HTTP Strict Transport Security (HSTS)'),
        description: i18n.t('Checking for HSTS header to enforce HTTPS'),
        ranking: 0,
        evaluate: (_data, ctx) => {
            if (!ctx.responseHeaders) {
                return headerUnavailableFinding('HSTS')
            }
            const hstsHeader = getSharedHeader(ctx, 'strict-transport-security')
            if (hstsHeader) {
                return {
                    status: 'pass',
                    message: 'HSTS header is configured',
                    details: `Strict-Transport-Security: ${hstsHeader}`,
                }
            }
            return {
                status: 'warning',
                message: 'HSTS header is not present',
                details:
                    'The server is not sending the Strict-Transport-Security header. This header enforces HTTPS connections and prevents protocol downgrade attacks. Consider adding: "Strict-Transport-Security: max-age=31536000; includeSubDomains"',
            }
        },
    },
    {
        id: 'server-header-exposure',
        title: i18n.t('Server Header Exposure'),
        description: i18n.t('Checking if server version information is exposed'),
        ranking: 0,
        evaluate: (_data, ctx) => {
            if (!ctx.responseHeaders) {
                return headerUnavailableFinding('Server')
            }
            const serverHeader = getSharedHeader(ctx, 'server')
            if (!serverHeader) {
                return {
                    status: 'pass',
                    message: 'Server header is not exposed',
                    details: 'The server does not disclose version information in the Server header, which is a good security practice.',
                }
            }
            return {
                status: 'warning',
                message: 'Server header exposes version information',
                details: `Server: ${serverHeader}. Exposing server version information can help attackers identify known vulnerabilities. Consider removing or obfuscating the Server header.`,
            }
        },
    },
    {
        id: 'coop-header',
        title: i18n.t('Cross-Origin-Opener-Policy (COOP)'),
        description: i18n.t('Checking for COOP header to isolate browsing context'),
        ranking: 0,
        evaluate: (_data, ctx) => {
            if (!ctx.responseHeaders) {
                return headerUnavailableFinding('COOP')
            }
            const coopHeader = getSharedHeader(ctx, 'cross-origin-opener-policy')
            if (!coopHeader) {
                return {
                    status: 'warning',
                    message: 'COOP header is not present',
                    details: 'The Cross-Origin-Opener-Policy header is not configured. This header helps protect against cross-origin attacks by isolating the browsing context. Consider adding: "Cross-Origin-Opener-Policy: same-origin".',
                }
            }
            const normalizedValue = coopHeader.toLowerCase().trim()
            if (normalizedValue === 'same-origin') {
                return {
                    status: 'pass',
                    message: 'COOP header is properly configured with same-origin',
                    details: `Cross-Origin-Opener-Policy: ${coopHeader}. This provides the strongest isolation.`,
                }
            }
            if (normalizedValue === 'same-origin-allow-popups') {
                return {
                    status: 'pass',
                    message: 'COOP header is configured with same-origin-allow-popups',
                    details: `Cross-Origin-Opener-Policy: ${coopHeader}. This provides good isolation while allowing popups.`,
                }
            }
            if (normalizedValue === 'unsafe-none') {
                return {
                    status: 'warning',
                    message: 'COOP header is set to unsafe-none',
                    details: `Cross-Origin-Opener-Policy: ${coopHeader}. Consider using "same-origin" or "same-origin-allow-popups" for better security.`,
                }
            }
            return {
                status: 'warning',
                message: `COOP header has unexpected value: ${coopHeader}`,
                details: 'Valid values are: same-origin, same-origin-allow-popups, or unsafe-none.',
            }
        },
    },
    {
        id: 'coep-header',
        title: i18n.t('Cross-Origin-Embedder-Policy (COEP)'),
        description: i18n.t('Checking for COEP header to control resource loading'),
        ranking: 0,
        evaluate: (_data, ctx) => {
            if (!ctx.responseHeaders) {
                return headerUnavailableFinding('COEP')
            }
            const coepHeader = getSharedHeader(ctx, 'cross-origin-embedder-policy')
            if (!coepHeader) {
                return {
                    status: 'warning',
                    message: 'COEP header is not present',
                    details: 'The Cross-Origin-Embedder-Policy header is not configured. This header, combined with COOP, enables cross-origin isolation and provides access to powerful features. Consider adding: "Cross-Origin-Embedder-Policy: require-corp".',
                }
            }
            const normalizedValue = coepHeader.toLowerCase().trim()
            if (normalizedValue === 'require-corp') {
                return {
                    status: 'pass',
                    message: 'COEP header is properly configured with require-corp',
                    details: `Cross-Origin-Embedder-Policy: ${coepHeader}. This ensures all resources are explicitly marked for cross-origin loading.`,
                }
            }
            if (normalizedValue === 'credentialless') {
                return {
                    status: 'pass',
                    message: 'COEP header is configured with credentialless',
                    details: `Cross-Origin-Embedder-Policy: ${coepHeader}. This loads cross-origin resources without credentials.`,
                }
            }
            if (normalizedValue === 'unsafe-none') {
                return {
                    status: 'warning',
                    message: 'COEP header is set to unsafe-none',
                    details: `Cross-Origin-Embedder-Policy: ${coepHeader}. Consider using "require-corp" for better security.`,
                }
            }
            return {
                status: 'warning',
                message: `COEP header has unexpected value: ${coepHeader}`,
                details: 'Valid values are: require-corp, credentialless, or unsafe-none.',
            }
        },
    },
    {
        id: 'corp-header',
        title: i18n.t('Cross-Origin-Resource-Policy (CORP)'),
        description: i18n.t('Checking for CORP header to control resource embedding'),
        ranking: 0,
        evaluate: (_data, ctx) => {
            if (!ctx.responseHeaders) {
                return headerUnavailableFinding('CORP')
            }
            const corpHeader = getSharedHeader(ctx, 'cross-origin-resource-policy')
            if (!corpHeader) {
                return {
                    status: 'warning',
                    message: 'CORP header is not present',
                    details: 'The Cross-Origin-Resource-Policy header is not configured. This header protects resources from being loaded by other origins. Consider adding: "Cross-Origin-Resource-Policy: same-origin".',
                }
            }
            const normalizedValue = corpHeader.toLowerCase().trim()
            if (normalizedValue === 'same-origin') {
                return {
                    status: 'pass',
                    message: 'CORP header is configured with same-origin',
                    details: `Cross-Origin-Resource-Policy: ${corpHeader}. Resources can only be loaded from the same origin.`,
                }
            }
            if (normalizedValue === 'same-site') {
                return {
                    status: 'pass',
                    message: 'CORP header is configured with same-site',
                    details: `Cross-Origin-Resource-Policy: ${corpHeader}. Resources can be loaded from the same site.`,
                }
            }
            if (normalizedValue === 'cross-origin') {
                return {
                    status: 'warning',
                    message: 'CORP header is set to cross-origin',
                    details: `Cross-Origin-Resource-Policy: ${corpHeader}. Resources can be loaded from any origin. Consider using "same-origin" or "same-site" for better security.`,
                }
            }
            return {
                status: 'warning',
                message: `CORP header has unexpected value: ${corpHeader}`,
                details: 'Valid values are: same-origin, same-site, or cross-origin.',
            }
        },
    },
    {
        id: 'cors-headers',
        title: i18n.t('CORS Headers Configuration'),
        description: i18n.t('Checking Access-Control-Allow-Origin and credentials configuration'),
        ranking: 0,
        evaluate: (_data, ctx) => {
            if (!ctx.responseHeaders) {
                return headerUnavailableFinding('CORS')
            }
            const allowOrigin = getSharedHeader(ctx, 'access-control-allow-origin')
            const allowCredentials = getSharedHeader(ctx, 'access-control-allow-credentials')

            if (allowOrigin === '*' && allowCredentials === 'true') {
                return {
                    status: 'fail',
                    message: 'Dangerous CORS configuration detected',
                    details: 'Access-Control-Allow-Origin is set to wildcard (*) with Access-Control-Allow-Credentials: true. This is a critical security vulnerability that allows any origin to make authenticated requests. Change Access-Control-Allow-Origin to specific trusted origins.',
                }
            }
            if (allowOrigin === '*') {
                return {
                    status: 'warning',
                    message: 'CORS allows all origins',
                    details: 'Access-Control-Allow-Origin: *. This allows any website to make requests to your API. Consider restricting to specific trusted origins unless this is intentional for a public API.',
                }
            }
            if (allowOrigin && allowCredentials === 'true') {
                return {
                    status: 'warning',
                    message: 'CORS allows credentials from specific origin',
                    details: `Access-Control-Allow-Origin: ${allowOrigin}, Access-Control-Allow-Credentials: true. Ensure this origin is trusted as it can make authenticated requests.`,
                }
            }
            if (allowOrigin) {
                return {
                    status: 'pass',
                    message: 'CORS configured with specific origin',
                    details: `Access-Control-Allow-Origin: ${allowOrigin}${allowCredentials ? `, Access-Control-Allow-Credentials: ${allowCredentials}` : ''}`,
                }
            }
            return {
                status: 'pass',
                message: 'No CORS headers present',
                details: 'Access-Control-Allow-Origin header is not set. This is appropriate if cross-origin requests are not needed.',
            }
        },
    },
    {
        id: 'csp-header',
        title: i18n.t('Content Security Policy (CSP)'),
        description: i18n.t('Checking for CSP header and violations'),
        ranking: 0,
        evaluate: (_data, ctx) => {
            if (!ctx.responseHeaders) {
                return headerUnavailableFinding('CSP')
            }
            const cspHeader =
                getSharedHeader(ctx, 'content-security-policy') ||
                getSharedHeader(ctx, 'content-security-policy-report-only')
            const isReportOnly = !getSharedHeader(ctx, 'content-security-policy')

            if (!cspHeader) {
                return {
                    status: 'warning',
                    message: 'CSP header is not present',
                    details:
                        'The server is not sending a Content-Security-Policy header. CSP helps prevent XSS attacks, clickjacking, and other code injection attacks. Consider implementing a CSP policy.',
                }
            }
            const hasDefaultSrc = cspHeader.includes('default-src')
            const hasScriptSrc = cspHeader.includes('script-src')
            const hasUnsafeInline = cspHeader.includes("'unsafe-inline'")
            const hasUnsafeEval = cspHeader.includes("'unsafe-eval'")

            const warnings = []
            if (isReportOnly) {
                warnings.push('CSP is in report-only mode')
            }
            if (hasUnsafeInline) {
                warnings.push("'unsafe-inline' is present")
            }
            if (hasUnsafeEval) {
                warnings.push("'unsafe-eval' is present")
            }
            if (!hasDefaultSrc && !hasScriptSrc) {
                warnings.push('No default-src or script-src directive')
            }

            const hasIssues = warnings.length > 0
            return {
                status: hasIssues ? 'warning' : 'pass',
                message: hasIssues
                    ? `CSP header configured with warnings: ${warnings.join(', ')}`
                    : 'CSP header is properly configured',
                details: `Content-Security-Policy${isReportOnly ? '-Report-Only' : ''}: ${cspHeader}`,
            }
        },
    },
]

export const useSecurityAudit = (config = {}) => {
    const engine = useDataEngine()
    const [auditStatus, setAuditStatus] = useState('idle') // idle, running, completed, error
    const [findings, setFindings] = useState([])
    const [progress, setProgress] = useState({ current: 0, total: 0 })
    const [apiResponses, setApiResponses] = useState([])

    const runAudit = useCallback(async (overrideConfig) => {
        setAuditStatus('running')
        setFindings([])
        setApiResponses([])

        const configToUse = overrideConfig || config
        const securityChecks = getSecurityChecks(configToUse)
        setProgress({ current: 0, total: securityChecks.length })

        // Prefetch shared data once so dependent checks can reuse it. Each
        // resource is independently captured so a failure in one (e.g. CORS)
        // doesn't cascade to unrelated checks.
        const ctx = {
            systemVersion: null,
            systemInfo: null,
            privilegedRoles: null,
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

        // Single fetch for response-header checks. Depends on systemInfo for
        // the contextPath; runs after the engine.query batch above so we can
        // build the URL. The same Promise is shared with SystemInfo and the
        // report exporter via fetchApiMeHeaders' module-level cache.
        try {
            ctx.responseHeaders = await fetchApiMeHeaders(
                ctx.systemInfo?.contextPath
            )
        } catch {
            // Network or CORS failure — checks fall back to the "unavailable" finding.
        }

        try {
            for (let i = 0; i < securityChecks.length; i++) {
                const check = securityChecks[i]

                // Add finding as "running"
                setFindings((prev) => [
                    ...prev,
                    {
                        id: check.id,
                        title: check.title,
                        description: check.description,
                        ranking: check.ranking || 0,
                        status: 'running',
                        message: null,
                        details: null,
                    },
                ])

                try {
                    // Resolve the check's data. Three modes:
                    //   - `check.fetch(engine, ctx)` for paged/multi-step fetches
                    //   - `check.query` for simple single-resource queries
                    //   - neither: the check consumes only the shared prefetch ctx
                    let data
                    if (check.fetch) {
                        data = await check.fetch(engine, ctx)
                    } else if (check.query) {
                        data = await engine.query(check.query)
                    } else {
                        data = null
                    }

                    // Store API response for console
                    setApiResponses((prev) => [
                        ...prev,
                        {
                            checkId: check.id,
                            checkTitle: check.title,
                            data: data,
                        },
                    ])

                    // Evaluate the result (handle both sync and async evaluate functions)
                    const result = await Promise.resolve(check.evaluate(data, ctx))

                    // Update the finding with results and sort by criticality and ranking
                    setFindings((prev) => {
                        const updated = prev.map((finding) =>
                            finding.id === check.id
                                ? {
                                      ...finding,
                                      status: result.status,
                                      message: result.message,
                                      details: result.details,
                                  }
                                : finding
                        )

                        // Sort by criticality (fail > warning > pass) and then by ranking
                        return updated.sort((a, b) => {
                            const statusOrder = { fail: 0, warning: 1, error: 2, pass: 3, running: 4 }
                            const statusDiff = statusOrder[a.status] - statusOrder[b.status]

                            if (statusDiff !== 0) {
                                return statusDiff
                            }

                            // Within same status, sort by ranking (higher ranking first)
                            return (b.ranking || 0) - (a.ranking || 0)
                        })
                    })
                } catch (error) {
                    // Allow the check to translate certain errors (e.g. a 404
                    // for a setting that doesn't exist on this DHIS2 version)
                    // into a meaningful status instead of a generic error.
                    const override = check.onError
                        ? await Promise.resolve(check.onError(error))
                        : null

                    setFindings((prev) =>
                        prev.map((finding) =>
                            finding.id === check.id
                                ? {
                                      ...finding,
                                      status: override?.status ?? 'error',
                                      message:
                                          override?.message ??
                                          `Error executing check: ${error.message}`,
                                      details: override?.details ?? null,
                                  }
                                : finding
                        )
                    )
                }

                setProgress({ current: i + 1, total: securityChecks.length })
            }

            setAuditStatus('completed')
        } catch (error) {
            setAuditStatus('error')
            console.error('Audit error:', error)
        }
    }, [engine, config])

    return {
        auditStatus,
        findings,
        progress,
        runAudit,
        apiResponses,
    }
}