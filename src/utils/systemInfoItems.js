import i18n from '@dhis2/d2-i18n'

// DHIS2's `memoryInfo` field has historically been returned as a free-form
// string ("Mem Total in JVM: 4096 Free in JVM: 2620 Max Limit: 4096") in some
// versions and a byte count in others. Normalize for display.
const formatMemory = (memoryInfo) => {
    if (memoryInfo === null || memoryInfo === undefined || memoryInfo === '') {
        return null
    }
    if (typeof memoryInfo === 'string') {
        const numbers = memoryInfo.match(/\d+/g)
        if (numbers && numbers.length >= 3) {
            return `${numbers[0]}/${numbers[1]}/${numbers[2]}`
        }
        return memoryInfo
    }
    return `${Math.round(memoryInfo / 1024 / 1024)} MB`
}

// Single source of truth for the system-info fields displayed both in the
// in-app SystemInfo panel and in the exported HTML report. Each entry is
// `{ key, label, value }`. Callers should fall back to a placeholder when
// `value` is null/undefined/empty.
export const getSystemInfoItems = (
    systemInfo = {},
    { webServer, appVersion } = {}
) => [
    {
        key: 'appVersion',
        label: i18n.t('Security Auditor Version'),
        value: appVersion,
    },
    {
        key: 'instanceBaseUrl',
        label: i18n.t('Server URL'),
        value:
            systemInfo.instanceBaseUrl ||
            (typeof window !== 'undefined' ? window.location.origin : ''),
    },
    { key: 'systemId', label: i18n.t('System ID'), value: systemInfo.systemId },
    { key: 'version', label: i18n.t('DHIS2 Version'), value: systemInfo.version },
    {
        key: 'revision',
        label: i18n.t('DHIS2 Build Revision'),
        value: systemInfo.revision,
    },
    { key: 'buildTime', label: i18n.t('Build Time'), value: systemInfo.buildTime },
    {
        key: 'osName',
        label: i18n.t('Operating System'),
        value: systemInfo.osName,
    },
    {
        key: 'osArchitecture',
        label: i18n.t('OS Architecture'),
        value: systemInfo.osArchitecture,
    },
    { key: 'osVersion', label: i18n.t('OS Version'), value: systemInfo.osVersion },
    {
        key: 'javaVersion',
        label: i18n.t('Java Version'),
        value: systemInfo.javaVersion,
    },
    {
        key: 'javaVendor',
        label: i18n.t('Java Vendor'),
        value: systemInfo.javaVendor,
    },
    {
        key: 'javaVmName',
        label: i18n.t('Java VM Name'),
        value: systemInfo.javaVmName,
    },
    {
        key: 'serverInfo',
        label: i18n.t('Servlet Container'),
        value: systemInfo.serverInfo,
    },
    { key: 'webServer', label: i18n.t('Web Server'), value: webServer },
    {
        key: 'databaseName',
        label: i18n.t('Database Name'),
        value: systemInfo.databaseInfo?.name,
    },
    {
        key: 'databaseVersion',
        label: i18n.t('Database Version'),
        value: systemInfo.databaseInfo?.databaseVersion,
    },
    {
        key: 'databaseUser',
        label: i18n.t('Database User'),
        value: systemInfo.databaseInfo?.user,
    },
    {
        key: 'externalDirectory',
        label: i18n.t('External Directory'),
        value: systemInfo.externalDirectory,
    },
    { key: 'cpuCores', label: i18n.t('CPU Cores'), value: systemInfo.cpuCores },
    {
        key: 'memory',
        label: i18n.t('Memory'),
        value: formatMemory(systemInfo.memoryInfo),
    },
    {
        key: 'systemUptime',
        label: i18n.t('System Uptime'),
        value: systemInfo.systemUptime,
    },
]

// Subset of fields included in the HTML report (compact summary).
const REPORT_KEYS = new Set([
    'appVersion',
    'instanceBaseUrl',
    'systemId',
    'version',
    'revision',
    'osName',
    'javaVersion',
    'serverInfo',
    'webServer',
    'databaseName',
    'databaseVersion',
    'externalDirectory',
])

export const getReportSystemInfoItems = (systemInfo, options) =>
    getSystemInfoItems(systemInfo, options).filter((item) => REPORT_KEYS.has(item.key))
