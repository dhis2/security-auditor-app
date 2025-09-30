import { useState, useCallback } from 'react'
import { useDataEngine } from '@dhis2/app-runtime'

// Security check definitions
const securityChecks = [
    {
        id: 'user-roles',
        title: 'User Roles Configuration',
        description: 'Checking for users with excessive privileges',
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
            const hasIssue = superUsers.length > 5

            return {
                status: hasIssue ? 'warning' : 'pass',
                message: hasIssue
                    ? `Found ${superUsers.length} user roles with ALL authorities. Consider limiting super user access.`
                    : `User roles configured appropriately (${superUsers.length} super user roles).`,
                details: hasIssue
                    ? superUsers.map((role) => role.name).join(', ')
                    : null,
            }
        },
    },
    {
        id: 'system-settings',
        title: 'System Security Settings',
        description: 'Verifying security-related system settings',
        query: {
            settings: {
                resource: 'systemSettings',
                params: {
                    key: [
                        'keyAccountRecovery',
                        'keySelfRegistrationNoRecaptcha',
                        'keyRequireAddToView',
                        'keyOpenIdProvider',
                    ],
                },
            },
        },
        evaluate: (data) => {
            const accountRecovery = data.settings?.keyAccountRecovery === 'true'
            const selfRegNoRecaptcha =
                data.settings?.keySelfRegistrationNoRecaptcha === 'true'
            const hasIssues = accountRecovery || selfRegNoRecaptcha

            return {
                status: hasIssues ? 'warning' : 'pass',
                message: hasIssues
                    ? 'Some security settings may need attention'
                    : 'System security settings look good',
                details: [
                    accountRecovery &&
                        'Account recovery is enabled (ensure email is properly configured)',
                    selfRegNoRecaptcha &&
                        'Self-registration without reCAPTCHA is enabled',
                ]
                    .filter(Boolean)
                    .join('; '),
            }
        },
    },
    {
        id: 'cors-whitelist',
        title: 'CORS Configuration',
        description: 'Checking CORS whitelist configuration',
        query: {
            corsWhitelist: {
                resource: 'systemSettings/corsWhitelist',
            },
        },
        evaluate: (data) => {
            const whitelist = data.corsWhitelist || []
            const hasWildcard = whitelist.some((url) => url.includes('*'))

            return {
                status: hasWildcard ? 'fail' : 'pass',
                message: hasWildcard
                    ? 'CORS whitelist contains wildcards - security risk!'
                    : whitelist.length > 0
                    ? `CORS properly configured with ${whitelist.length} allowed origins`
                    : 'CORS whitelist is empty',
                details: hasWildcard ? whitelist.join(', ') : null,
            }
        },
    },
    {
        id: 'user-credentials',
        title: 'User Account Security',
        description: 'Analyzing user credentials and password policies',
        query: {
            users: {
                resource: 'users',
                params: {
                    fields: 'id,username,disabled,lastLogin,userCredentials[passwordLastUpdated]',
                    paging: false,
                    filter: 'disabled:eq:false',
                },
            },
        },
        evaluate: (data) => {
            const users = data.users.users
            const oneYearAgo = new Date()
            oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1)

            const staleUsers = users.filter((user) => {
                const lastLogin = user.lastLogin
                    ? new Date(user.lastLogin)
                    : null
                return !lastLogin || lastLogin < oneYearAgo
            })

            const hasIssue = staleUsers.length > 0

            return {
                status: hasIssue ? 'warning' : 'pass',
                message: hasIssue
                    ? `Found ${staleUsers.length} users who haven't logged in for over a year`
                    : 'All active users have recent activity',
                details: hasIssue
                    ? `Consider disabling inactive accounts: ${staleUsers.slice(0, 5).map((u) => u.username).join(', ')}${staleUsers.length > 5 ? '...' : ''}`
                    : null,
            }
        },
    },
]

export const useSecurityAudit = () => {
    const engine = useDataEngine()
    const [auditStatus, setAuditStatus] = useState('idle') // idle, running, completed, error
    const [findings, setFindings] = useState([])
    const [progress, setProgress] = useState({ current: 0, total: 0 })

    const runAudit = useCallback(async () => {
        setAuditStatus('running')
        setFindings([])
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
                        status: 'running',
                        message: null,
                        details: null,
                    },
                ])

                try {
                    // Execute the query
                    const data = await engine.query(check.query)

                    // Evaluate the result
                    const result = check.evaluate(data)

                    // Update the finding with results
                    setFindings((prev) =>
                        prev.map((finding) =>
                            finding.id === check.id
                                ? {
                                      ...finding,
                                      status: result.status,
                                      message: result.message,
                                      details: result.details,
                                  }
                                : finding
                        )
                    )
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
    }, [engine])

    return {
        auditStatus,
        findings,
        progress,
        runAudit,
    }
}