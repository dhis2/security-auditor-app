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
                    ? `Connection is using insecure HTTP protocol`
                    : 'Connection is secured with HTTPS',
                details: hasIssue
                    ? `Current protocol: ${window.location.protocol}. HTTPS should be used to encrypt data in transit and prevent man-in-the-middle attacks.`
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
]
