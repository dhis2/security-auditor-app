import i18n from '@dhis2/d2-i18n'
import { settingsUnavailableFinding } from '../helpers'

// systemSettings keys pre-fetched as a single batched request.
export const PREFETCHED_SETTINGS_KEYS = [
    'minPasswordLength',
    'credentialsExpires',
    'enforceVerifiedEmail',
    'lockMultipleFailedLogins',
]

export const getSettingsChecks = (config) => [
    {
        id: 'password-policy',
        title: i18n.t('Password Policy Configuration'),
        description: i18n.t('Verifying minimum password length requirements'),
        ranking: 0,
        evaluate: (_data, ctx) => {
            if (!ctx.systemSettings) {
                return settingsUnavailableFinding('minimum password length')
            }
            const raw = ctx.systemSettings.minPasswordLength
            const minPasswordLength = parseInt(raw, 10)
            const requiredLength = config.minPasswordLength || 8

            // Treat malformed/missing values as a warning rather than passing
            // a default 0 < requiredLength comparison silently.
            if (!Number.isFinite(minPasswordLength)) {
                return {
                    status: 'warning',
                    message: 'Minimum password length is not configured or has a non-numeric value',
                    details: `Raw value: ${JSON.stringify(raw)}. Set minPasswordLength to at least ${requiredLength}.`,
                }
            }

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
            const raw = ctx.systemSettings.credentialsExpires
            const expiryDays = parseInt(raw, 10)

            // A non-numeric or missing value is treated as "not configured"
            // — a warning, not a silent pass.
            if (!Number.isFinite(expiryDays)) {
                return {
                    status: 'warning',
                    message: 'Password expiry is not configured or has a non-numeric value',
                    details: `Raw value: ${JSON.stringify(raw)}. Configure credentialsExpires to enable forced password changes.`,
                }
            }

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
            const enforceVerifiedEmail = settings.enforceVerifiedEmail === 'true'
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
                settings.lockMultipleFailedLogins === 'true'
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
]
