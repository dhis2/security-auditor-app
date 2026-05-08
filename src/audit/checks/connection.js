import i18n from '@dhis2/d2-i18n'

// Connection-level checks that don't fit cleanly into authority/user/settings/header
// buckets: HTTPS protocol detection (purely client-side) and the CORS whitelist
// configuration check (a single legacy API call).
export const getConnectionChecks = () => [
    {
        id: 'https-connection',
        title: i18n.t('HTTPS Connection Security'),
        description: i18n.t('Verifying secure connection to the server'),
        ranking: 0,
        // The existing check uses `me` as a "dummy query" so the runner has
        // some data to pass through. We preserve that behavior — the actual
        // determination is `window.location.protocol`.
        query: {
            me: {
                resource: 'me',
                params: { fields: 'id' },
            },
        },
        evaluate: () => {
            const isHttps = window.location.protocol === 'https:'
            const hasIssue = !isHttps

            return {
                status: hasIssue ? 'fail' : 'pass',
                message: hasIssue
                    ? i18n.t('Connection is using insecure HTTP protocol')
                    : i18n.t('Connection is secured with HTTPS'),
                details: hasIssue
                    ? i18n.t(
                          'Current protocol: {{protocol}}. HTTPS should be used to encrypt data in transit and prevent man-in-the-middle attacks.',
                          { protocol: window.location.protocol }
                      )
                    : null,
            }
        },
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

            let message
            if (hasWildcard) {
                message = i18n.t('CORS whitelist contains wildcards - security risk!')
            } else if (whitelist.length > 0) {
                message = i18n.t(
                    'CORS whitelist is configured with {{count}} allowed origins',
                    { count: whitelist.length }
                )
            } else {
                message = i18n.t('CORS whitelist is empty')
            }

            return {
                status: hasWildcard
                    ? 'fail'
                    : whitelist.length > 0
                    ? 'warning'
                    : 'pass',
                message,
                details:
                    hasWildcard || whitelist.length > 0
                        ? whitelist.join(', ')
                        : null,
            }
        },
    },
]
