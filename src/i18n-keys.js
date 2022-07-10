import i18n from './locales/index.js'

export const i18nKeys = {

    browserInfo: {
        title: i18n.t('Browser'),
        label: i18n.t('Browser'),
        description: i18n.t(
            'Review the security status of a browser used to connect to this DHIS2 instance'
        ),
        actionText: i18n.t('Overview Browser Information'),
    },

    dataStatistics: {
        title: i18n.t('Data Statistics'),
        label: i18n.t('Data Statistics'),
        description: i18n.t(
            'Browse the number of objects in the database, like data elements, indicators, data sets and data values.'
        ),
        actionText: i18n.t('Overview Data Statistics'),
    },
}

export default i18nKeys
