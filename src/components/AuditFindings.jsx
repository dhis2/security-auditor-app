import React from 'react'
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
} from '@dhis2/ui'
import i18n from '@dhis2/d2-i18n'
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
            )}
        </div>
    )
}