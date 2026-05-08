import i18n from '@dhis2/d2-i18n'
import { getSharedHeader, headerUnavailableFinding } from '../helpers'

export const getHeaderChecks = () => [
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
            if (!hstsHeader) {
                return {
                    status: 'warning',
                    message: 'HSTS header is not present',
                    details:
                        'The server is not sending the Strict-Transport-Security header. This header enforces HTTPS connections and prevents protocol downgrade attacks. Consider adding: "Strict-Transport-Security: max-age=31536000; includeSubDomains"',
                }
            }

            // Parse directives. The header is a semicolon-separated list:
            //   max-age=31536000; includeSubDomains; preload
            // The value after `max-age=` must be entirely digits — `parseInt`
            // alone would silently accept `max-age=31536000abc`.
            const directives = hstsHeader
                .split(';')
                .map((d) => d.trim().toLowerCase())
            const maxAgeMatch = directives
                .map((d) => d.match(/^max-age=(\d+)$/))
                .find(Boolean)
            const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : NaN
            const ONE_YEAR = 31_536_000
            const ONE_DAY = 86_400

            if (!Number.isFinite(maxAge) || maxAge <= 0) {
                return {
                    status: 'warning',
                    message: 'HSTS header is present but max-age is missing or invalid',
                    details: `Strict-Transport-Security: ${hstsHeader}. A valid max-age (in seconds, digits only) is required for HSTS to take effect.`,
                }
            }
            if (maxAge < ONE_DAY) {
                return {
                    status: 'warning',
                    message: `HSTS max-age is too short (${maxAge}s)`,
                    details: `Strict-Transport-Security: ${hstsHeader}. A max-age below 1 day provides effectively no protection. Recommended: max-age=31536000 (1 year) with includeSubDomains.`,
                }
            }
            if (maxAge < ONE_YEAR) {
                return {
                    status: 'warning',
                    message: `HSTS max-age is below the recommended 1 year (${maxAge}s)`,
                    details: `Strict-Transport-Security: ${hstsHeader}. Increase max-age to at least 31536000 (1 year) for stronger protection against downgrade attacks.`,
                }
            }
            return {
                status: 'pass',
                message: `HSTS header is configured with max-age=${maxAge}`,
                details: `Strict-Transport-Security: ${hstsHeader}`,
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

            // Parse the policy into a directive map so we can inspect the
            // *values* rather than relying on substring matches that pass
            // wildly permissive policies like `default-src *`. Both directive
            // names AND source values are lowercased — keyword sources like
            // 'unsafe-inline' are case-insensitive in practice and a policy
            // like default-src 'UNSAFE-INLINE' should not slip past.
            const directives = {}
            for (const part of cspHeader.split(';')) {
                const tokens = part.trim().split(/\s+/).filter(Boolean)
                if (tokens.length === 0) {
                    continue
                }
                const [name, ...sources] = tokens
                directives[name.toLowerCase()] = sources.map((s) => s.toLowerCase())
            }

            const BROAD_SOURCES = new Set(['*', 'http:', 'https:', 'data:'])
            const hasBroad = (sources) =>
                sources && sources.some((s) => BROAD_SOURCES.has(s))

            // The "fetch directive" governing scripts is script-src if present,
            // otherwise default-src. If neither exists, no policy applies to scripts.
            const fetchSources =
                directives['script-src'] || directives['default-src'] || null

            const warnings = []
            if (isReportOnly) {
                warnings.push('CSP is in report-only mode')
            }

            // 1) script-src / default-src
            if (!fetchSources) {
                warnings.push('no default-src or script-src directive')
            } else {
                if (hasBroad(fetchSources)) {
                    warnings.push(
                        `script-src/default-src contains a broad source (${fetchSources
                            .filter((s) => BROAD_SOURCES.has(s))
                            .join(', ')})`
                    )
                }
                if (fetchSources.includes("'unsafe-inline'")) {
                    warnings.push(
                        "'unsafe-inline' allowed in script-src/default-src"
                    )
                }
                if (fetchSources.includes("'unsafe-eval'")) {
                    warnings.push(
                        "'unsafe-eval' allowed in script-src/default-src"
                    )
                }
            }

            // 2) object-src — should be 'none' to neutralize legacy plugin attacks.
            const objectSrc =
                directives['object-src'] || directives['default-src'] || null
            const objectSrcIsNone =
                objectSrc && objectSrc.length === 1 && objectSrc[0] === "'none'"
            const objectSrcIsLockedDown =
                objectSrc &&
                objectSrc.length > 0 &&
                !hasBroad(objectSrc) &&
                !objectSrc.includes("'unsafe-inline'") &&
                !objectSrc.includes("'unsafe-eval'")
            if (!objectSrc) {
                warnings.push("object-src is unset (recommend object-src 'none')")
            } else if (!objectSrcIsNone && !objectSrcIsLockedDown) {
                warnings.push('object-src is not strictly locked down')
            }

            // 3) base-uri — controls <base> hijacking. Should be 'none' or 'self'.
            const baseUri = directives['base-uri']
            if (!baseUri) {
                warnings.push(
                    "base-uri is unset (recommend base-uri 'none' or 'self')"
                )
            } else if (hasBroad(baseUri)) {
                warnings.push('base-uri contains a broad source')
            }

            // 4) frame-ancestors — modern replacement for X-Frame-Options.
            //    Should be 'none' or 'self' to prevent clickjacking.
            const frameAncestors = directives['frame-ancestors']
            if (!frameAncestors) {
                warnings.push(
                    "frame-ancestors is unset (recommend 'none' or 'self' for clickjacking protection)"
                )
            } else if (hasBroad(frameAncestors)) {
                warnings.push('frame-ancestors contains a broad source')
            }

            // 5) strict-dynamic — informational. Indicates a nonce/hash-based
            //    policy that trusts loaded scripts to load their own deps.
            //    Don't warn; just surface it in details.
            const usesStrictDynamic =
                fetchSources && fetchSources.includes("'strict-dynamic'")

            const hasIssues = warnings.length > 0
            return {
                status: hasIssues ? 'warning' : 'pass',
                message: hasIssues
                    ? `CSP header configured with warnings: ${warnings.join('; ')}`
                    : 'CSP header is properly configured',
                details: `Content-Security-Policy${isReportOnly ? '-Report-Only' : ''}: ${cspHeader}${usesStrictDynamic ? " (uses 'strict-dynamic')" : ''}`,
            }
        },
    },
]
