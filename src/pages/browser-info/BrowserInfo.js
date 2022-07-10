import { useConfig } from '@dhis2/app-runtime'
import { useDataQuery } from '@dhis2/app-runtime'
import { Card, NoticeBox, CircularLoader, CenteredContent } from '@dhis2/ui'
import PropTypes from 'prop-types'
import React from 'react'
import PageHeader from '../../components/PageHeader/PageHeader.js'
import { i18nKeys } from '../../i18n-keys.js'
import styles from './BrowserInfo.module.css'

const BrowserInfo = ({ sectionKey }) => {

    return (
        <>
            <pre>
            { JSON.stringify(useConfig(), null, 2) }
            </pre>

        </>
    )


}

BrowserInfo.propTypes = {
    sectionKey: PropTypes.string.isRequired,
}

export default BrowserInfo
