import React from 'react'
import { Button, Card } from '@dhis2/ui'
import i18n from '@dhis2/d2-i18n'
import { useSecurityAudit } from '../hooks/useSecurityAudit'
import { AuditFindings } from './AuditFindings'
import classes from './SecurityAuditor.module.css'

export const SecurityAuditor = () => {
    const { auditStatus, findings, progress, runAudit } = useSecurityAudit()

    const isRunning = auditStatus === 'running'

    return (
        <div className={classes.container}>
            <Card className={classes.header}>
                <div className={classes.headerContent}>
                    <div>
                        <h2 className={classes.title}>
                            {i18n.t('Security Auditor')}
                        </h2>
                        <p className={classes.subtitle}>
                            {i18n.t(
                                'Analyze your DHIS2 instance for security vulnerabilities and configuration issues'
                            )}
                        </p>
                    </div>
                    <Button
                        primary
                        large
                        onClick={runAudit}
                        disabled={isRunning}
                    >
                        {isRunning
                            ? i18n.t('Auditing...')
                            : i18n.t('Start Audit')}
                    </Button>
                </div>
            </Card>

            <AuditFindings
                findings={findings}
                auditStatus={auditStatus}
                progress={progress}
            />
        </div>
    )
}