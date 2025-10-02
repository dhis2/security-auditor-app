import React from 'react'
import './locales'
import { useDataQuery } from '@dhis2/app-runtime'
import { Card, NoticeBox, CircularLoader } from '@dhis2/ui'
import i18n from '@dhis2/d2-i18n'
import { SecurityAuditor } from './components/SecurityAuditor'

const currentUserQuery = {
    me: {
        resource: 'me',
        params: {
            fields: 'authorities',
        },
    },
}

const MyApp = () => {
    const { loading, error, data } = useDataQuery(currentUserQuery)

    if (loading) {
        return (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
                <CircularLoader />
            </div>
        )
    }

    if (error) {
        return (
            <div style={{ padding: '20px' }}>
                <NoticeBox error title={i18n.t('Error')}>
                    {i18n.t('Failed to load user information')}
                </NoticeBox>
            </div>
        )
    }

    const authorities = data?.me?.authorities || []
    const hasAllAuthority = authorities.includes('ALL')

    if (!hasAllAuthority) {
        return (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', padding: '20px' }}>
                <Card style={{ maxWidth: '600px', padding: '40px', textAlign: 'center' }}>
                    <h2 style={{ marginBottom: '20px', color: '#212934' }}>
                        {i18n.t('Security Auditor')}
                    </h2>
                    <NoticeBox warning title={i18n.t('Administrator Access Required')}>
                        {i18n.t('This tool is available for administrators only. You need the ALL authority to access the Security Auditor.')}
                    </NoticeBox>
                </Card>
            </div>
        )
    }

    return <SecurityAuditor />
}

export default MyApp
