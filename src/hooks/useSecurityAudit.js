import { useState, useCallback } from 'react'
import { useDataEngine } from '@dhis2/app-runtime'

// Security check definitions (config will be passed in)
const getSecurityChecks = (config) => [
    {
        id: 'user-roles',
        title: 'User Roles Configuration',
        description: 'Checking for users with excessive privileges',
        ranking: 0,
        query: {
            userRoles: {
                resource: 'userRoles',
                params: {
                    fields: 'id,name,users,authorities',
                    paging: false,
                },
            },
        },
        evaluate: (data) => {
            const superUsers = data.userRoles.userRoles.filter((role) =>
                role.authorities.includes('ALL')
            )
            const maxAllowed = config.maxSuperUserRoles || 5
            const hasIssue = superUsers.length > maxAllowed

            return {
                status: hasIssue ? 'warning' : 'pass',
                message: hasIssue
                    ? `Found ${superUsers.length} user roles with ALL authorities. Consider limiting super user access (max: ${maxAllowed}).`
                    : `User roles configured appropriately (${superUsers.length} super user roles, max: ${maxAllowed}).`,
                details: hasIssue
                    ? superUsers.map((role) => role.name).join(', ')
                    : null,
            }
        },
    },
    {
        id: 'cors-whitelist',
        title: 'CORS Configuration',
        description: 'Checking CORS whitelist configuration',
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
        title: 'Users Never Logged In',
        description: 'Checking for active accounts that have never been used',
        ranking: 0,
        query: {
            users: {
                resource: 'users',
                params: {
                    fields: 'id,username,disabled,lastLogin,created',
                    paging: false,
                    filter: 'disabled:eq:false',
                },
            },
        },
        evaluate: (data) => {
            const users = data.users.users
            const neverLoggedIn = users.filter(
                (user) => !user.lastLogin || user.lastLogin === ''
            )

            const hasIssue = neverLoggedIn.length > 0

            return {
                status: hasIssue ? 'warning' : 'pass',
                message: hasIssue
                    ? `Found ${neverLoggedIn.length} active accounts that have never logged in`
                    : 'All active users have logged in at least once',
                details: hasIssue
                    ? `Consider removing unused accounts: ${neverLoggedIn.slice(0, 5).map((u) => u.username).join(', ')}${neverLoggedIn.length > 5 ? ` and ${neverLoggedIn.length - 5} more` : ''}`
                    : null,
            }
        },
    },
    {
        id: 'users-inactive-3-months',
        title: 'Inactive User Accounts',
        description: 'Checking for accounts with no recent activity',
        ranking: 0,
        query: {
            users: {
                resource: 'users',
                params: {
                    fields: 'id,username,disabled,lastLogin',
                    paging: false,
                    filter: 'disabled:eq:false',
                },
            },
        },
        evaluate: (data) => {
            const users = data.users.users
            const maxMonths = config.maxInactiveMonths || 3
            const thresholdDate = new Date()
            thresholdDate.setMonth(thresholdDate.getMonth() - maxMonths)

            const inactiveUsers = users.filter((user) => {
                if (!user.lastLogin || user.lastLogin === '') {
                    return false // Exclude users who never logged in (handled by other check)
                }
                const lastLogin = new Date(user.lastLogin)
                return lastLogin < thresholdDate
            })

            const hasIssue = inactiveUsers.length > 0

            return {
                status: hasIssue ? 'warning' : 'pass',
                message: hasIssue
                    ? `Found ${inactiveUsers.length} users who haven't logged in for ${maxMonths}+ months`
                    : `All users with login history have recent activity (within ${maxMonths} months)`,
                details: hasIssue
                    ? `Consider disabling inactive accounts: ${inactiveUsers.slice(0, 5).map((u) => u.username).join(', ')}${inactiveUsers.length > 5 ? ` and ${inactiveUsers.length - 5} more` : ''}`
                    : null,
            }
        },
    },
    {
        id: 'password-age',
        title: 'Password Age Verification',
        description: 'Checking for stale or unchanged passwords',
        ranking: 0,
        query: {
            users: {
                resource: 'users',
                params: {
                    fields: 'id,username,disabled,userCredentials[passwordLastUpdated]',
                    paging: false,
                    filter: 'disabled:eq:false',
                },
            },
        },
        evaluate: (data) => {
            const users = data.users.users
            const maxAgeDays = config.maxPasswordAgeDays || 365
            const thresholdDate = new Date()
            thresholdDate.setDate(thresholdDate.getDate() - maxAgeDays)

            const stalePasswords = users.filter((user) => {
                const passwordLastUpdated =
                    user.userCredentials?.passwordLastUpdated
                if (!passwordLastUpdated || passwordLastUpdated === '') {
                    return true // Never changed
                }
                const lastUpdated = new Date(passwordLastUpdated)
                return lastUpdated < thresholdDate
            })

            const hasIssue = stalePasswords.length > 0

            return {
                status: hasIssue ? 'warning' : 'pass',
                message: hasIssue
                    ? `Found ${stalePasswords.length} users with passwords older than ${maxAgeDays} days or never changed`
                    : `All user passwords are up to date (within ${maxAgeDays} days)`,
                details: hasIssue
                    ? `Users with stale passwords: ${stalePasswords.slice(0, 5).map((u) => u.username).join(', ')}${stalePasswords.length > 5 ? ` and ${stalePasswords.length - 5} more` : ''}`
                    : null,
            }
        },
    },
    {
        id: 'password-policy',
        title: 'Password Policy Configuration',
        description: 'Verifying minimum password length requirements',
        ranking: 0,
        query: {
            settings: {
                resource: 'systemSettings',
                params: {
                    key: ['minPasswordLength'],
                },
            },
        },
        evaluate: (data) => {
            const minPasswordLength = parseInt(
                data.settings?.minPasswordLength || 0,
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
        title: 'Password Expiry Policy',
        description: 'Checking if forced password changes are enabled',
        ranking: 0,
        query: {
            settings: {
                resource: 'systemSettings',
                params: {
                    key: ['credentialsExpires'],
                },
            },
        },
        evaluate: (data) => {
            const credentialsExpires =
                data.settings?.credentialsExpires || '0'
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
        title: 'Email Verification Enforcement',
        description: 'Checking if email verification is enforced',
        ranking: 0,
        query: {
            settings: {
                resource: 'systemSettings',
                params: {
                    key: ['enforceVerifiedEmail'],
                },
            },
        },
        evaluate: (data) => {
            const enforceVerifiedEmail =
                data.settings?.enforceVerifiedEmail === 'true'
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
        title: 'HTTPS Connection Security',
        description: 'Verifying secure connection to the server',
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
        title: 'Default Admin Password Check',
        description: 'Checking if admin account uses default password',
        ranking: 10,
        query: {
            adminUser: {
                resource: 'users',
                params: {
                    fields: 'id,username,userCredentials[passwordLastUpdated]',
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
            const passwordLastUpdated =
                adminUser.userCredentials?.passwordLastUpdated
            const hasDefaultPassword =
                !passwordLastUpdated || passwordLastUpdated === ''

            return {
                status: hasDefaultPassword ? 'fail' : 'pass',
                message: hasDefaultPassword
                    ? 'Admin account is using default password!'
                    : 'Admin password has been changed',
                details: hasDefaultPassword
                    ? 'CRITICAL: The admin account password has never been changed. Change it immediately to prevent unauthorized access.'
                    : null,
            }
        },
    },
    {
        id: 'account-lockout',
        title: 'Account Lockout Policy',
        description: 'Checking if account lockout after failed login attempts is enabled',
        ranking: 0,
        query: {
            settings: {
                resource: 'systemSettings',
                params: {
                    key: ['lockMultipleFailedLogins'],
                },
            },
        },
        evaluate: (data) => {
            const lockMultipleFailedLogins =
                data.settings?.lockMultipleFailedLogins === 'true'
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
        title: 'HTTP Strict Transport Security (HSTS)',
        description: 'Checking for HSTS header to enforce HTTPS',
        ranking: 0,
        query: {
            // We need to make an async check, so use a dummy query
            me: {
                resource: 'me',
                params: {
                    fields: 'id',
                },
            },
        },
        evaluate: async (data) => {
            try {
                // Make a fetch request to check response headers
                const response = await fetch(
                    `${window.location.origin}/api/me`,
                    {
                        method: 'GET',
                        credentials: 'include',
                    }
                )

                const hstsHeader = response.headers.get(
                    'strict-transport-security'
                )

                if (hstsHeader) {
                    return {
                        status: 'pass',
                        message: 'HSTS header is configured',
                        details: `Strict-Transport-Security: ${hstsHeader}`,
                    }
                } else {
                    return {
                        status: 'warning',
                        message: 'HSTS header is not present',
                        details:
                            'The server is not sending the Strict-Transport-Security header. This header enforces HTTPS connections and prevents protocol downgrade attacks. Consider adding: "Strict-Transport-Security: max-age=31536000; includeSubDomains"',
                    }
                }
            } catch (error) {
                return {
                    status: 'warning',
                    message: 'Unable to check HSTS header',
                    details: `Error checking HSTS header: ${error.message}. This may be due to CORS restrictions. Manually verify if the server sends the "Strict-Transport-Security" header.`,
                }
            }
        },
    },
    {
        id: 'server-header-exposure',
        title: 'Server Header Exposure',
        description: 'Checking if server version information is exposed',
        ranking: 0,
        query: {
            me: {
                resource: 'me',
                params: {
                    fields: 'id',
                },
            },
        },
        evaluate: async (data) => {
            try {
                const response = await fetch(
                    `${window.location.origin}/api/me`,
                    {
                        method: 'GET',
                        credentials: 'include',
                    }
                )

                const serverHeader = response.headers.get('server')

                if (!serverHeader) {
                    return {
                        status: 'pass',
                        message: 'Server header is not exposed',
                        details: 'The server does not disclose version information in the Server header, which is a good security practice.',
                    }
                } else {
                    return {
                        status: 'warning',
                        message: 'Server header exposes version information',
                        details: `Server: ${serverHeader}. Exposing server version information can help attackers identify known vulnerabilities. Consider removing or obfuscating the Server header.`,
                    }
                }
            } catch (error) {
                return {
                    status: 'error',
                    message: 'Unable to check Server header',
                    details: `Error checking Server header: ${error.message}`,
                }
            }
        },
    },
    {
        id: 'coop-header',
        title: 'Cross-Origin-Opener-Policy (COOP)',
        description: 'Checking for COOP header to isolate browsing context',
        ranking: 0,
        query: {
            me: {
                resource: 'me',
                params: {
                    fields: 'id',
                },
            },
        },
        evaluate: async (data) => {
            try {
                const response = await fetch(
                    `${window.location.origin}/api/me`,
                    {
                        method: 'GET',
                        credentials: 'include',
                    }
                )

                const coopHeader = response.headers.get('cross-origin-opener-policy')

                if (coopHeader) {
                    // Check the value of COOP
                    const normalizedValue = coopHeader.toLowerCase().trim()

                    if (normalizedValue === 'same-origin') {
                        return {
                            status: 'pass',
                            message: 'COOP header is properly configured with same-origin',
                            details: `Cross-Origin-Opener-Policy: ${coopHeader}. This provides the strongest isolation.`,
                        }
                    } else if (normalizedValue === 'same-origin-allow-popups') {
                        return {
                            status: 'pass',
                            message: 'COOP header is configured with same-origin-allow-popups',
                            details: `Cross-Origin-Opener-Policy: ${coopHeader}. This provides good isolation while allowing popups.`,
                        }
                    } else if (normalizedValue === 'unsafe-none') {
                        return {
                            status: 'warning',
                            message: 'COOP header is set to unsafe-none',
                            details: `Cross-Origin-Opener-Policy: ${coopHeader}. Consider using "same-origin" or "same-origin-allow-popups" for better security.`,
                        }
                    } else {
                        return {
                            status: 'warning',
                            message: `COOP header has unexpected value: ${coopHeader}`,
                            details: 'Valid values are: same-origin, same-origin-allow-popups, or unsafe-none.',
                        }
                    }
                } else {
                    return {
                        status: 'warning',
                        message: 'COOP header is not present',
                        details: 'The Cross-Origin-Opener-Policy header is not configured. This header helps protect against cross-origin attacks by isolating the browsing context. Consider adding: "Cross-Origin-Opener-Policy: same-origin".',
                    }
                }
            } catch (error) {
                return {
                    status: 'error',
                    message: 'Unable to check COOP header',
                    details: `Error checking COOP header: ${error.message}. This may be due to CORS restrictions.`,
                }
            }
        },
    },
    {
        id: 'coep-header',
        title: 'Cross-Origin-Embedder-Policy (COEP)',
        description: 'Checking for COEP header to control resource loading',
        ranking: 0,
        query: {
            me: {
                resource: 'me',
                params: {
                    fields: 'id',
                },
            },
        },
        evaluate: async (data) => {
            try {
                const response = await fetch(
                    `${window.location.origin}/api/me`,
                    {
                        method: 'GET',
                        credentials: 'include',
                    }
                )

                const coepHeader = response.headers.get('cross-origin-embedder-policy')

                if (coepHeader) {
                    const normalizedValue = coepHeader.toLowerCase().trim()

                    if (normalizedValue === 'require-corp') {
                        return {
                            status: 'pass',
                            message: 'COEP header is properly configured with require-corp',
                            details: `Cross-Origin-Embedder-Policy: ${coepHeader}. This ensures all resources are explicitly marked for cross-origin loading.`,
                        }
                    } else if (normalizedValue === 'credentialless') {
                        return {
                            status: 'pass',
                            message: 'COEP header is configured with credentialless',
                            details: `Cross-Origin-Embedder-Policy: ${coepHeader}. This loads cross-origin resources without credentials.`,
                        }
                    } else if (normalizedValue === 'unsafe-none') {
                        return {
                            status: 'warning',
                            message: 'COEP header is set to unsafe-none',
                            details: `Cross-Origin-Embedder-Policy: ${coepHeader}. Consider using "require-corp" for better security.`,
                        }
                    } else {
                        return {
                            status: 'warning',
                            message: `COEP header has unexpected value: ${coepHeader}`,
                            details: 'Valid values are: require-corp, credentialless, or unsafe-none.',
                        }
                    }
                } else {
                    return {
                        status: 'warning',
                        message: 'COEP header is not present',
                        details: 'The Cross-Origin-Embedder-Policy header is not configured. This header, combined with COOP, enables cross-origin isolation and provides access to powerful features. Consider adding: "Cross-Origin-Embedder-Policy: require-corp".',
                    }
                }
            } catch (error) {
                return {
                    status: 'error',
                    message: 'Unable to check COEP header',
                    details: `Error checking COEP header: ${error.message}. This may be due to CORS restrictions.`,
                }
            }
        },
    },
    {
        id: 'corp-header',
        title: 'Cross-Origin-Resource-Policy (CORP)',
        description: 'Checking for CORP header to control resource embedding',
        ranking: 0,
        query: {
            me: {
                resource: 'me',
                params: {
                    fields: 'id',
                },
            },
        },
        evaluate: async (data) => {
            try {
                const response = await fetch(
                    `${window.location.origin}/api/me`,
                    {
                        method: 'GET',
                        credentials: 'include',
                    }
                )

                const corpHeader = response.headers.get('cross-origin-resource-policy')

                if (corpHeader) {
                    const normalizedValue = corpHeader.toLowerCase().trim()

                    if (normalizedValue === 'same-origin') {
                        return {
                            status: 'pass',
                            message: 'CORP header is configured with same-origin',
                            details: `Cross-Origin-Resource-Policy: ${corpHeader}. Resources can only be loaded from the same origin.`,
                        }
                    } else if (normalizedValue === 'same-site') {
                        return {
                            status: 'pass',
                            message: 'CORP header is configured with same-site',
                            details: `Cross-Origin-Resource-Policy: ${corpHeader}. Resources can be loaded from the same site.`,
                        }
                    } else if (normalizedValue === 'cross-origin') {
                        return {
                            status: 'warning',
                            message: 'CORP header is set to cross-origin',
                            details: `Cross-Origin-Resource-Policy: ${corpHeader}. Resources can be loaded from any origin. Consider using "same-origin" or "same-site" for better security.`,
                        }
                    } else {
                        return {
                            status: 'warning',
                            message: `CORP header has unexpected value: ${corpHeader}`,
                            details: 'Valid values are: same-origin, same-site, or cross-origin.',
                        }
                    }
                } else {
                    return {
                        status: 'warning',
                        message: 'CORP header is not present',
                        details: 'The Cross-Origin-Resource-Policy header is not configured. This header protects resources from being loaded by other origins. Consider adding: "Cross-Origin-Resource-Policy: same-origin".',
                    }
                }
            } catch (error) {
                return {
                    status: 'error',
                    message: 'Unable to check CORP header',
                    details: `Error checking CORP header: ${error.message}. This may be due to CORS restrictions.`,
                }
            }
        },
    },
    {
        id: 'cors-headers',
        title: 'CORS Headers Configuration',
        description: 'Checking Access-Control-Allow-Origin and credentials configuration',
        ranking: 0,
        query: {
            me: {
                resource: 'me',
                params: {
                    fields: 'id',
                },
            },
        },
        evaluate: async (data) => {
            try {
                const response = await fetch(
                    `${window.location.origin}/api/me`,
                    {
                        method: 'GET',
                        credentials: 'include',
                    }
                )

                const allowOrigin = response.headers.get('access-control-allow-origin')
                const allowCredentials = response.headers.get('access-control-allow-credentials')

                // Check for dangerous combinations
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
            } catch (error) {
                return {
                    status: 'error',
                    message: 'Unable to check CORS headers',
                    details: `Error checking CORS headers: ${error.message}`,
                }
            }
        },
    },
    {
        id: 'csp-header',
        title: 'Content Security Policy (CSP)',
        description: 'Checking for CSP header and violations',
        ranking: 0,
        query: {
            me: {
                resource: 'me',
                params: {
                    fields: 'id',
                },
            },
        },
        evaluate: async (data) => {
            try {
                // Make a fetch request to check response headers
                const response = await fetch(
                    `${window.location.origin}/api/me`,
                    {
                        method: 'GET',
                        credentials: 'include',
                    }
                )

                const cspHeader =
                    response.headers.get('content-security-policy') ||
                    response.headers.get('content-security-policy-report-only')

                const isReportOnly = !response.headers.get(
                    'content-security-policy'
                )

                if (cspHeader) {
                    // Check for common CSP directives
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
                } else {
                    return {
                        status: 'warning',
                        message: 'CSP header is not present',
                        details:
                            'The server is not sending a Content-Security-Policy header. CSP helps prevent XSS attacks, clickjacking, and other code injection attacks. Consider implementing a CSP policy.',
                    }
                }
            } catch (error) {
                return {
                    status: 'warning',
                    message: 'Unable to check CSP header',
                    details: `Error checking CSP header: ${error.message}. This may be due to CORS restrictions. Manually verify if the server sends the "Content-Security-Policy" header.`,
                }
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
                    // Execute the query
                    const data = await engine.query(check.query)

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
                    const result = await Promise.resolve(check.evaluate(data))

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
                    // Handle individual check errors
                    setFindings((prev) =>
                        prev.map((finding) =>
                            finding.id === check.id
                                ? {
                                      ...finding,
                                      status: 'error',
                                      message: `Error executing check: ${error.message}`,
                                      details: null,
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