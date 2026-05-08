import { createContext, useContext, useMemo } from 'react'
import { useDataQuery } from '@dhis2/app-runtime'

// Fields needed by the SystemInfo panel and the HTML report exporter.
// Anything outside this set is wasted bandwidth.
const FIELDS = [
    'version',
    'revision',
    'buildTime',
    'systemId',
    'instanceBaseUrl',
    'contextPath',
    'osName',
    'osArchitecture',
    'osVersion',
    'javaVersion',
    'javaVendor',
    'javaVmName',
    'serverInfo',
    'databaseInfo',
    'externalDirectory',
    'cpuCores',
    'memoryInfo',
    'systemUptime',
].join(',')

const query = {
    systemInfo: {
        resource: 'system/info',
        params: { fields: FIELDS },
    },
}

const InstanceInfoContext = createContext(null)

// Single owner of the /api/system/info data. Replaces the per-component
// useDataQuery calls in SystemInfo.jsx and AuditFindings.jsx so the same
// payload isn't fetched twice when both surfaces are used.
export const InstanceInfoProvider = ({ children }) => {
    const { loading, error, data } = useDataQuery(query)

    const value = useMemo(
        () => ({
            loading,
            error,
            systemInfo: data?.systemInfo || null,
        }),
        [loading, error, data]
    )

    return (
        <InstanceInfoContext.Provider value={value}>
            {children}
        </InstanceInfoContext.Provider>
    )
}

export const useInstanceInfo = () => {
    const ctx = useContext(InstanceInfoContext)
    if (!ctx) {
        throw new Error(
            'useInstanceInfo must be used inside an <InstanceInfoProvider>'
        )
    }
    return ctx
}
