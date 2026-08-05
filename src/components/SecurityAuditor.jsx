import { useState } from 'react'
import { Card, Tab, TabBar } from '@dhis2/ui'
import i18n from '@dhis2/d2-i18n'
import { useSecurityAudit } from '../hooks/useSecurityAudit'
import { useAuditConfig } from '../hooks/useAuditConfig'
import { useAppsAudit } from '../hooks/useAppsAudit'
import { AuditFindings } from './AuditFindings'
import { AppsAudit } from './AppsAudit'
import { ConfigurationPanel } from './ConfigurationPanel'
import { SystemInfo } from './SystemInfo'
import { Console } from './Console'
import classes from './SecurityAuditor.module.css'

export const SecurityAuditor = () => {
    const { config } = useAuditConfig()
    const { auditStatus, findings, progress, runAudit, apiResponses } =
        useSecurityAudit(config)
    const apps = useAppsAudit(config)
    const [activeTab, setActiveTab] = useState('audit')

    const handleStartAudit = () => {
        setActiveTab('audit')
        runAudit(config)
    }

    const handleStartAppsAudit = () => {
        setActiveTab('apps')
        apps.runAppsAudit(config)
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
                </div>
            </Card>

            <TabBar className={classes.tabs}>
                <Tab
                    selected={activeTab === 'audit'}
                    onClick={() => setActiveTab('audit')}
                >
                    {i18n.t('DHIS2 Audit')}
                </Tab>
                <Tab
                    selected={activeTab === 'apps'}
                    onClick={() => setActiveTab('apps')}
                >
                    {i18n.t('Apps Audit')}
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
                <Tab
                    selected={activeTab === 'console'}
                    onClick={() => setActiveTab('console')}
                >
                    {i18n.t('Console')}
                </Tab>
            </TabBar>

            {activeTab === 'audit' && (
                <AuditFindings
                    findings={findings}
                    auditStatus={auditStatus}
                    progress={progress}
                    onStartAudit={handleStartAudit}
                />
            )}

            {activeTab === 'apps' && (
                <AppsAudit
                    status={apps.status}
                    results={apps.results}
                    progress={apps.progress}
                    currentAppKey={apps.currentAppKey}
                    error={apps.error}
                    onStart={handleStartAppsAudit}
                    retireInfo={apps.retireInfo}
                    signatures={apps.signatures}
                    signatureError={apps.signatureError}
                    baseline={apps.baseline}
                    baselineError={apps.baselineError}
                    savingBaseline={apps.savingBaseline}
                    onAcceptBaseline={apps.acceptBaseline}
                />
            )}

            {activeTab === 'config' && (
                <ConfigurationPanel
                    signatures={apps.signatures}
                    signaturesStale={apps.signaturesStale}
                    signatureError={apps.signatureError}
                    refreshingSignatures={apps.refreshingSignatures}
                    onFetchSignatures={apps.fetchSignatures}
                />
            )}

            {activeTab === 'systeminfo' && <SystemInfo />}

            {activeTab === 'console' && <Console apiResponses={apiResponses} />}
        </div>
    )
}
