import React from 'react'
import { Card, CircularLoader, NoticeBox } from '@dhis2/ui'
import { useDataQuery } from '@dhis2/app-runtime'
import i18n from '@dhis2/d2-i18n'
import classes from './SystemInfo.module.css'

const query = {
    systemInfo: {
        resource: 'system/info',
    },
}

export const SystemInfo = () => {
    const { loading, error, data } = useDataQuery(query)

    if (loading) {
        return (
            <Card className={classes.card}>
                <CircularLoader />
            </Card>
        )
    }

    if (error) {
        return (
            <Card className={classes.card}>
                <NoticeBox error title={i18n.t('Error')}>
                    {`${i18n.t('Failed to load system information')}: ${error.message}`}
                </NoticeBox>
            </Card>
        )
    }

    const systemInfo = data?.systemInfo || {}
    const appVersion = '1.0.0' // Version from package.json

    const infoItems = [
        {
            label: i18n.t('Security Auditor Version'),
            value: appVersion,
        },
        {
            label: i18n.t('DHIS2 Version'),
            value: systemInfo.version || i18n.t('N/A'),
        },
        {
            label: i18n.t('DHIS2 Build Revision'),
            value: systemInfo.revision || i18n.t('N/A'),
        },
        {
            label: i18n.t('Build Time'),
            value: systemInfo.buildTime || i18n.t('N/A'),
        },
        {
            label: i18n.t('Operating System'),
            value: systemInfo.osName || i18n.t('N/A'),
        },
        {
            label: i18n.t('OS Architecture'),
            value: systemInfo.osArchitecture || i18n.t('N/A'),
        },
        {
            label: i18n.t('OS Version'),
            value: systemInfo.osVersion || i18n.t('N/A'),
        },
        {
            label: i18n.t('Java Version'),
            value: systemInfo.javaVersion || i18n.t('N/A'),
        },
        {
            label: i18n.t('Java Vendor'),
            value: systemInfo.javaVendor || i18n.t('N/A'),
        },
        {
            label: i18n.t('Java VM Name'),
            value: systemInfo.javaVmName || i18n.t('N/A'),
        },
        {
            label: i18n.t('Servlet Container'),
            value: systemInfo.serverInfo || i18n.t('N/A'),
        },
        {
            label: i18n.t('Database Name'),
            value: systemInfo.databaseInfo?.name || i18n.t('N/A'),
        },
        {
            label: i18n.t('Database User'),
            value: systemInfo.databaseInfo?.user || i18n.t('N/A'),
        },
        {
            label: i18n.t('CPU Cores'),
            value: systemInfo.cpuCores || i18n.t('N/A'),
        },
        {
            label: i18n.t('Memory'),
            value: systemInfo.memoryInfo
                ? typeof systemInfo.memoryInfo === 'string'
                    ? systemInfo.memoryInfo
                    : `${Math.round(systemInfo.memoryInfo / 1024 / 1024)} MB`
                : i18n.t('N/A'),
        },
        {
            label: i18n.t('System Uptime'),
            value: systemInfo.systemUptime || i18n.t('N/A'),
        },
    ]

    return (
        <Card className={classes.card}>
            <div className={classes.header}>
                <h3 className={classes.title}>{i18n.t('System Information')}</h3>
                <p className={classes.subtitle}>
                    {i18n.t(
                        'Information about the DHIS2 instance and server environment'
                    )}
                </p>
            </div>

            <div className={classes.infoGrid}>
                {infoItems.map((item, index) => (
                    <div key={index} className={classes.infoItem}>
                        <dt className={classes.label}>{item.label}</dt>
                        <dd className={classes.value}>{item.value}</dd>
                    </div>
                ))}
            </div>
        </Card>
    )
}
