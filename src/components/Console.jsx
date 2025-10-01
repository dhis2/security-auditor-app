import React from 'react'
import { Card } from '@dhis2/ui'
import i18n from '@dhis2/d2-i18n'
import classes from './Console.module.css'

export const Console = ({ apiResponses }) => {
    return (
        <Card className={classes.card}>
            <div className={classes.header}>
                <h3 className={classes.title}>{i18n.t('API Console')}</h3>
                <p className={classes.subtitle}>
                    {i18n.t(
                        'Raw API responses from security audit checks'
                    )}
                </p>
            </div>

            <div className={classes.consoleContent}>
                {!apiResponses || apiResponses.length === 0 ? (
                    <div className={classes.emptyState}>
                        <p>
                            {i18n.t(
                                'No API responses yet. Run an audit to see the data.'
                            )}
                        </p>
                    </div>
                ) : (
                    apiResponses.map((item, index) => (
                        <div key={index} className={classes.responseBlock}>
                            <div className={classes.responseHeader}>
                                <span className={classes.checkId}>
                                    {item.checkId}
                                </span>
                                <span className={classes.checkTitle}>
                                    {item.checkTitle}
                                </span>
                            </div>
                            <pre className={classes.jsonContent}>
                                {JSON.stringify(item.data, null, 2)}
                            </pre>
                        </div>
                    ))
                )}
            </div>
        </Card>
    )
}
