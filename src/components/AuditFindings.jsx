import React, { useState } from 'react'
import {
    Card,
    NoticeBox,
    CircularLoader,
    Table,
    TableHead,
    TableRowHead,
    TableCellHead,
    TableBody,
    TableRow,
    TableCell,
    Button,
} from '@dhis2/ui'
import { useDataQuery } from '@dhis2/app-runtime'
import i18n from '@dhis2/d2-i18n'
import classes from './AuditFindings.module.css'

const systemInfoQuery = {
    systemInfo: {
        resource: 'system/info',
    },
}

const StatusBadge = ({ status }) => {
    const getStatusConfig = (status) => {
        switch (status) {
            case 'pass':
                return { label: i18n.t('Pass'), className: classes.statusPass }
            case 'warning':
                return {
                    label: i18n.t('Warning'),
                    className: classes.statusWarning,
                }
            case 'fail':
                return { label: i18n.t('Fail'), className: classes.statusFail }
            case 'error':
                return {
                    label: i18n.t('Error'),
                    className: classes.statusError,
                }
            case 'running':
                return {
                    label: i18n.t('Running'),
                    className: classes.statusRunning,
                }
            default:
                return {
                    label: i18n.t('Unknown'),
                    className: classes.statusUnknown,
                }
        }
    }

    const config = getStatusConfig(status)

    return (
        <span className={`${classes.statusBadge} ${config.className}`}>
            {status === 'running' && (
                <CircularLoader small className={classes.loader} />
            )}
            {config.label}
        </span>
    )
}

export const AuditFindings = ({ findings, auditStatus, progress }) => {
    const [generating, setGenerating] = useState(false)
    const [webServer, setWebServer] = useState('Loading...')
    const { data: systemInfoData } = useDataQuery(systemInfoQuery)

    const generatePDFReport = async () => {
        setGenerating(true)

        try {
            // Fetch web server info
            let serverHeader = 'Unable to detect'
            try {
                const response = await fetch(
                    `${window.location.origin}/api/me`,
                    {
                        method: 'GET',
                        credentials: 'include',
                    }
                )
                serverHeader = response.headers.get('server') || 'Not disclosed'
            } catch (error) {
                serverHeader = 'Unable to detect'
            }

            const systemInfo = systemInfoData?.systemInfo || {}
            const reportDate = new Date().toLocaleString()
            const appVersion = '1.0.0' // Version from package.json

            // Create HTML content for the report
            let htmlContent = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>DHIS2 Security Audit Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
            color: #333;
        }
        h1 {
            color: #2c5aa0;
            border-bottom: 3px solid #2c5aa0;
            padding-bottom: 10px;
        }
        h2 {
            color: #2c5aa0;
            margin-top: 30px;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 5px;
        }
        .header-info {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th {
            background-color: #2c5aa0;
            color: white;
            padding: 12px;
            text-align: left;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #e0e0e0;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .status-pass {
            color: #2e7d32;
            font-weight: bold;
        }
        .status-warning {
            color: #e65100;
            font-weight: bold;
        }
        .status-fail {
            color: #c62828;
            font-weight: bold;
        }
        .status-error {
            color: #6a1b9a;
            font-weight: bold;
        }
        .details {
            font-size: 0.9em;
            color: #666;
            font-style: italic;
            margin-top: 5px;
        }
        .system-info {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 15px;
        }
        .info-item {
            padding: 10px;
            background-color: #f9f9f9;
            border-left: 3px solid #2c5aa0;
        }
        .info-label {
            font-weight: bold;
            color: #666;
            font-size: 0.85em;
            text-transform: uppercase;
        }
        .info-value {
            margin-top: 3px;
            color: #333;
        }
    </style>
</head>
<body>
    <h1>DHIS2 Security Audit Report</h1>
    <div class="header-info">
        <strong>Report Generated:</strong> ${reportDate}<br>
        <strong>Total Checks:</strong> ${findings.length}<br>
        <strong>Failed:</strong> ${findings.filter(f => f.status === 'fail').length}<br>
        <strong>Warnings:</strong> ${findings.filter(f => f.status === 'warning').length}<br>
        <strong>Passed:</strong> ${findings.filter(f => f.status === 'pass').length}
    </div>

    <h2>System Information</h2>
    <div class="system-info">
        <div class="info-item">
            <div class="info-label">Security Auditor Version</div>
            <div class="info-value">${appVersion}</div>
        </div>
        <div class="info-item">
            <div class="info-label">Server URL</div>
            <div class="info-value">${window.location.origin}</div>
        </div>
        <div class="info-item">
            <div class="info-label">System ID</div>
            <div class="info-value">${systemInfo.systemId || 'N/A'}</div>
        </div>
        <div class="info-item">
            <div class="info-label">DHIS2 Version</div>
            <div class="info-value">${systemInfo.version || 'N/A'}</div>
        </div>
        <div class="info-item">
            <div class="info-label">Build Revision</div>
            <div class="info-value">${systemInfo.revision || 'N/A'}</div>
        </div>
        <div class="info-item">
            <div class="info-label">Operating System</div>
            <div class="info-value">${systemInfo.osName || 'N/A'} ${systemInfo.osVersion || ''}</div>
        </div>
        <div class="info-item">
            <div class="info-label">Java Version</div>
            <div class="info-value">${systemInfo.javaVersion || 'N/A'}</div>
        </div>
        <div class="info-item">
            <div class="info-label">Servlet Container</div>
            <div class="info-value">${systemInfo.serverInfo || 'N/A'}</div>
        </div>
        <div class="info-item">
            <div class="info-label">Web Server</div>
            <div class="info-value">${serverHeader}</div>
        </div>
        <div class="info-item">
            <div class="info-label">Database</div>
            <div class="info-value">${systemInfo.databaseInfo?.name || 'N/A'}</div>
        </div>
    </div>

    <h2>Security Findings</h2>
    <table>
        <thead>
            <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Result</th>
            </tr>
        </thead>
        <tbody>
`

            findings.forEach((finding) => {
                const statusClass = `status-${finding.status}`
                htmlContent += `
            <tr>
                <td>
                    <strong>${finding.title}</strong><br>
                    <span style="font-size: 0.9em; color: #666;">${finding.description}</span>
                </td>
                <td class="${statusClass}">${finding.status.toUpperCase()}</td>
                <td>
                    ${finding.message || ''}
                    ${finding.details ? `<div class="details">${finding.details}</div>` : ''}
                </td>
            </tr>
`
            })

            htmlContent += `
        </tbody>
    </table>
</body>
</html>
`

            // Create blob and download
            const blob = new Blob([htmlContent], { type: 'text/html' })
            const url = URL.createObjectURL(blob)
            const link = document.createElement('a')
            link.href = url
            link.download = `dhis2-security-audit-${new Date().toISOString().split('T')[0]}.html`
            document.body.appendChild(link)
            link.click()
            document.body.removeChild(link)
            URL.revokeObjectURL(url)
        } catch (error) {
            console.error('Error generating report:', error)
        } finally {
            setGenerating(false)
        }
    }

    if (auditStatus === 'idle') {
        return (
            <NoticeBox title={i18n.t('Ready to audit')}>
                {i18n.t(
                    'Click "Start Audit" to begin the security assessment.'
                )}
            </NoticeBox>
        )
    }

    if (auditStatus === 'error') {
        return (
            <NoticeBox error title={i18n.t('Audit Error')}>
                {i18n.t(
                    'An error occurred while running the security audit. Please try again.'
                )}
            </NoticeBox>
        )
    }

    const hasFailures = findings.some((f) => f.status === 'fail')
    const hasWarnings = findings.some((f) => f.status === 'warning')

    return (
        <div className={classes.container}>
            {auditStatus === 'running' && (
                <NoticeBox title={i18n.t('Audit in Progress')}>
                    {i18n.t('Running security checks... {{current}} of {{total}}', {
                        current: progress.current,
                        total: progress.total,
                    })}
                </NoticeBox>
            )}

            {auditStatus === 'completed' && (
                <NoticeBox
                    title={i18n.t('Audit Completed')}
                    warning={hasWarnings && !hasFailures}
                    error={hasFailures}
                    success={!hasWarnings && !hasFailures}
                >
                    {hasFailures
                        ? i18n.t(
                              'Critical security issues found. Please review the findings below.'
                          )
                        : hasWarnings
                        ? i18n.t(
                              'Security audit completed with warnings. Review recommended.'
                          )
                        : i18n.t('All security checks passed successfully!')}
                </NoticeBox>
            )}

            {findings.length > 0 && (
                <>
                    <Card className={classes.card}>
                        <Table>
                            <TableHead>
                                <TableRowHead>
                                    <TableCellHead>
                                        {i18n.t('Check')}
                                    </TableCellHead>
                                    <TableCellHead>
                                        {i18n.t('Status')}
                                    </TableCellHead>
                                    <TableCellHead>
                                        {i18n.t('Result')}
                                    </TableCellHead>
                                </TableRowHead>
                            </TableHead>
                            <TableBody>
                                {findings.map((finding) => (
                                    <TableRow key={finding.id}>
                                        <TableCell>
                                            <div className={classes.checkInfo}>
                                                <strong>{finding.title}</strong>
                                                <div className={classes.description}>
                                                    {finding.description}
                                                </div>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <StatusBadge status={finding.status} />
                                        </TableCell>
                                        <TableCell>
                                            <div className={classes.result}>
                                                {finding.message && (
                                                    <div>{finding.message}</div>
                                                )}
                                                {finding.details && (
                                                    <div
                                                        className={
                                                            classes.details
                                                        }
                                                    >
                                                        {finding.details}
                                                    </div>
                                                )}
                                            </div>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </Card>

                    {auditStatus === 'completed' && (
                        <div className={classes.reportButton}>
                            <Button
                                onClick={generatePDFReport}
                                disabled={generating}
                            >
                                {generating
                                    ? i18n.t('Generating...')
                                    : i18n.t('Save Report')}
                            </Button>
                        </div>
                    )}
                </>
            )}
        </div>
    )
}