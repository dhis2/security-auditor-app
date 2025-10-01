import React, { useState } from 'react'
import { Button, Card, Tab, TabBar } from '@dhis2/ui'
import i18n from '@dhis2/d2-i18n'
import { useSecurityAudit } from '../hooks/useSecurityAudit'
import { useAuditConfig } from '../hooks/useAuditConfig'
import { AuditFindings } from './AuditFindings'
import { ConfigurationPanel } from './ConfigurationPanel'
import { SystemInfo } from './SystemInfo'
import classes from './SecurityAuditor.module.css'

export const SecurityAuditor = () => {
    const { config, reloadConfig } = useAuditConfig()
    const { auditStatus, findings, progress, runAudit } = useSecurityAudit(config)
    const [activeTab, setActiveTab] = useState('audit')

    const isRunning = auditStatus === 'running'

    const handleStartAudit = async () => {
        // Navigate to Audit Results tab
        setActiveTab('audit')
        // Reload configuration before starting audit to ensure latest settings are used
        const freshConfig = await reloadConfig()
        // Pass the fresh config directly to runAudit to avoid stale closure issues
        runAudit(freshConfig)
    }

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
                        onClick={handleStartAudit}
                        disabled={isRunning}
                    >
                        {isRunning
                            ? i18n.t('Auditing...')
                            : i18n.t('Start Audit')}
                    </Button>
                </div>
            </Card>

            <TabBar className={classes.tabs}>
                <Tab
                    selected={activeTab === 'audit'}
                    onClick={() => setActiveTab('audit')}
                >
                    {i18n.t('Audit Results')}
                </Tab>
                <Tab
                    selected={activeTab === 'config'}
                    onClick={() => setActiveTab('config')}
                >
                    {i18n.t('Configuration')}
                </Tab>
                <Tab
                    selected={activeTab === 'systeminfo'}
                    onClick={() => setActiveTab('systeminfo')}
                >
                    {i18n.t('System Info')}
                </Tab>
            </TabBar>

            {activeTab === 'audit' && (
                <AuditFindings
                    findings={findings}
                    auditStatus={auditStatus}
                    progress={progress}
                />
            )}

            {activeTab === 'config' && <ConfigurationPanel />}

            {activeTab === 'systeminfo' && <SystemInfo />}
        </div>
    )
}