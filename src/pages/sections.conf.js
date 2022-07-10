import { i18nKeys } from '../i18n-keys.js'

import BrowserInfo from './browser-info/BrowserInfo.js'
import DataStatistics from './data-statistics/DataStatistics.js'

export const sections = [
    {

        key: 'browser',
        path: '/browser-info',
        component: BrowserInfo,
        info: {
            label: i18nKeys.browserInfo.label,
            description: i18nKeys.browserInfo.description,
            actionText: i18nKeys.browserInfo.actionText,
            docs: 'securityAuditor_browserInfo',
        },
    },
    {
        key: 'statistics',
        path: '/data-statistics',
        component: DataStatistics,
        info: {
            label: i18nKeys.dataStatistics.label,
            description: i18nKeys.dataStatistics.description,
            actionText: i18nKeys.dataStatistics.actionText,
            docs: 'dataAdmin_dataStatistics',
        },
    },
]

export const getDocsKeyForSection = (sectionKey) =>
    sections.find((section) => section.key === sectionKey)?.info.docs || ''
