import i18n from '@dhis2/d2-i18n'
import {
    fetchAuthorityHolders,
    summarizeAuthorityHolders,
} from '../helpers'

// Authorities pre-fetched as the audit's shared "privileged roles" set.
export const PRIVILEGED_AUTHORITIES = [
    'ALL',
    'F_PUBLIC_ROUTE_ADD',
    'F_IMPERSONATE_USER',
    'F_SYSTEM_SETTING',
]

export const getAuthorityChecks = (config) => [
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
]
