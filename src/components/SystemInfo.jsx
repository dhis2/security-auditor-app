import { useState, useEffect } from 'react'
import { Card, CircularLoader, NoticeBox } from '@dhis2/ui'
import i18n from '@dhis2/d2-i18n'
import { useInstanceInfo } from '../hooks/useInstanceInfo'
import { APP_VERSION as appVersion } from '../version'
import { getServerHeader } from '../utils/instanceInfo'
import { getSystemInfoItems } from '../utils/systemInfoItems'
import classes from './SystemInfo.module.css'

export const SystemInfo = () => {
    const { loading, error, systemInfo } = useInstanceInfo()
    const [webServer, setWebServer] = useState(i18n.t('Loading...'))

    useEffect(() => {
        if (!systemInfo) {
            return
        }
        let cancelled = false
        getServerHeader(systemInfo.contextPath).then((header) => {
            if (cancelled) {
                return
            }
            setWebServer(
                header === null
                    ? i18n.t('Unable to detect')
                    : header || i18n.t('Not disclosed')
            )
        })
        return () => {
            cancelled = true
        }
    }, [systemInfo])

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

    const naLabel = i18n.t('N/A')
    const infoItems = getSystemInfoItems(systemInfo || {}, {
        webServer,
        appVersion,
    }).map((item) => ({
        label: item.label,
        value: item.value || naLabel,
    }))

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
