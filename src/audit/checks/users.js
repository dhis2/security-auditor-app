import i18n from '@dhis2/d2-i18n'
import { fetchAllPaged } from '../../utils/pagination'
import { passwordLastUpdatedField } from '../../utils/version'
import {
    getPasswordLastUpdated,
    timestampsRoughlyEqual,
} from '../helpers'

export const getUserChecks = (config) => [
    {
        id: 'users-never-logged-in',
        title: i18n.t('Users Never Logged In'),
        description: i18n.t('Checking for active accounts that have never been used'),
        ranking: 0,
        fetch: async (engine) => {
            const users = await fetchAllPaged(
                engine,
                {
                    resource: 'users',
                    params: {
                        fields: 'id,username',
                        filter: ['disabled:eq:false', 'lastLogin:null'],
                    },
                },
                config.maxAuditPages ? { maxPages: config.maxAuditPages } : undefined
            )
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
            const users = await fetchAllPaged(
                engine,
                {
                    resource: 'users',
                    params: {
                        fields: 'id,username,lastLogin',
                        filter: 'disabled:eq:false',
                        inactiveMonths: months,
                    },
                },
                config.maxAuditPages ? { maxPages: config.maxAuditPages } : undefined
            )
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

            const pageOpts = config.maxAuditPages
                ? { maxPages: config.maxAuditPages }
                : undefined
            const [stale, neverSet] = await Promise.all([
                fetchAllPaged(
                    engine,
                    {
                        resource: 'users',
                        params: {
                            fields: 'id,username',
                            filter: [
                                'disabled:eq:false',
                                `${pwField}:lt:${thresholdIso}`,
                            ],
                        },
                    },
                    pageOpts
                ),
                fetchAllPaged(
                    engine,
                    {
                        resource: 'users',
                        params: {
                            fields: 'id,username',
                            filter: ['disabled:eq:false', `${pwField}:null`],
                        },
                    },
                    pageOpts
                ),
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
]
