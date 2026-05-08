import { useState } from 'react'
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
import i18n from '@dhis2/d2-i18n'
import { useInstanceInfo } from '../hooks/useInstanceInfo'
import { APP_VERSION as appVersion } from '../version'
import { downloadBlob } from '../utils/download'
import { escapeHtml } from '../utils/html'
import { getServerHeader } from '../utils/instanceInfo'
import { getReportSystemInfoItems } from '../utils/systemInfoItems'
import classes from './AuditFindings.module.css'

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
    const [exportError, setExportError] = useState(null)
    const { systemInfo: sharedSystemInfo } = useInstanceInfo()

    const generatePDFReport = async () => {
        setGenerating(true)
        setExportError(null)

        try {
            const systemInfo = sharedSystemInfo || {}
            const fetchedHeader = await getServerHeader(systemInfo.contextPath)
            const serverHeader =
                fetchedHeader === null
                    ? i18n.t('Unable to detect')
                    : fetchedHeader || i18n.t('Not disclosed')
            const reportDate = new Date().toLocaleString()

            // Create HTML content for the report
            let htmlContent = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>${escapeHtml(i18n.t('DHIS2 Security Audit Report'))}</title>
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
    <h1>${escapeHtml(i18n.t('DHIS2 Security Audit Report'))}</h1>
    <div class="header-info">
        <strong>${escapeHtml(i18n.t('Report Generated:'))}</strong> ${escapeHtml(reportDate)}<br>
        <strong>${escapeHtml(i18n.t('Total Checks:'))}</strong> ${findings.length}<br>
        <strong>${escapeHtml(i18n.t('Failed:'))}</strong> ${findings.filter(f => f.status === 'fail').length}<br>
        <strong>${escapeHtml(i18n.t('Warnings:'))}</strong> ${findings.filter(f => f.status === 'warning').length}<br>
        <strong>${escapeHtml(i18n.t('Passed:'))}</strong> ${findings.filter(f => f.status === 'pass').length}
    </div>

    <h2>${escapeHtml(i18n.t('System Information'))}</h2>
    <div class="system-info">
${getReportSystemInfoItems(systemInfo, { webServer: serverHeader, appVersion })
    .map(
        (item) => `        <div class="info-item">
            <div class="info-label">${escapeHtml(item.label)}</div>
            <div class="info-value">${escapeHtml(item.value || i18n.t('N/A'))}</div>
        </div>`
    )
    .join('\n')}
    </div>

    <h2>${escapeHtml(i18n.t('Security Findings'))}</h2>
    <table>
        <thead>
            <tr>
                <th>${escapeHtml(i18n.t('Check'))}</th>
                <th>${escapeHtml(i18n.t('Status'))}</th>
                <th>${escapeHtml(i18n.t('Result'))}</th>
            </tr>
        </thead>
        <tbody>
`

            const STATUS_CLASSES = {
                pass: 'status-pass',
                warning: 'status-warning',
                fail: 'status-fail',
                error: 'status-error',
            }
            findings.forEach((finding) => {
                const statusClass = STATUS_CLASSES[finding.status] || 'status-error'
                const statusLabel = (finding.status || 'unknown').toUpperCase()
                htmlContent += `
            <tr>
                <td>
                    <strong>${escapeHtml(finding.title)}</strong><br>
                    <span style="font-size: 0.9em; color: #666;">${escapeHtml(finding.description)}</span>
                </td>
                <td class="${statusClass}">${escapeHtml(statusLabel)}</td>
                <td>
                    ${escapeHtml(finding.message || '')}
                    ${finding.details ? `<div class="details">${escapeHtml(finding.details)}</div>` : ''}
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

            const blob = new Blob([htmlContent], { type: 'text/html' })
            downloadBlob(
                blob,
                `dhis2-security-audit-${new Date().toISOString().split('T')[0]}.html`
            )
        } catch (error) {
            setExportError(error.message || i18n.t('Unknown error'))
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
                            {exportError && (
                                <NoticeBox
                                    error
                                    title={i18n.t('Failed to generate report')}
                                >
                                    {exportError}
                                </NoticeBox>
                            )}
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