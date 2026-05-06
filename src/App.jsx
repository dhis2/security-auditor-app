import React from 'react'
import './locales'
import { useDataQuery } from '@dhis2/app-runtime'
import { NoticeBox, CircularLoader } from '@dhis2/ui'
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

    return (
        <>
            {!hasAllAuthority && (
                <div style={{ padding: '20px 20px 0' }}>
                    <NoticeBox warning title={i18n.t('Limited Access')}>
                        {i18n.t('You do not have the ALL authority. Some audit checks may fail or return incomplete results, as the Security Auditor is designed for administrators with full access.')}
                    </NoticeBox>
                </div>
            )}
            <SecurityAuditor />
        </>
    )
}

export default MyApp
