import { getAuthorityChecks, PRIVILEGED_AUTHORITIES } from './authorities'
import { getConnectionChecks } from './connection'
import { getHeaderChecks } from './headers'
import { getSettingsChecks, PREFETCHED_SETTINGS_KEYS } from './settings'
import { getUserChecks } from './users'

// Re-export the constants the runner needs to construct the prefetch query.
export { PRIVILEGED_AUTHORITIES, PREFETCHED_SETTINGS_KEYS }

// Compose all checks in category order. The runner sorts findings by
// criticality (fail > warning > error > pass) and then by `ranking` after
// each one resolves, so the source order here only affects fetch sequence,
// not the final display.
export const getSecurityChecks = (config) => [
    ...getAuthorityChecks(config),
    ...getUserChecks(config),
    ...getSettingsChecks(config),
    ...getConnectionChecks(),
    ...getHeaderChecks(),
]
