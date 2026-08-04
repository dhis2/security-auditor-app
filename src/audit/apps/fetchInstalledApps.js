const APPS_QUERY = {
    apps: { resource: 'apps' },
}

// Fetch the list of installed DHIS2 apps from /api/apps. The endpoint has
// historically returned either a bare array or { apps: [...] } depending on
// the DHIS2 version; this helper normalizes both shapes to a flat array.
//
// Used by:
//   - runAppsAudit (enumerates apps, then fetches each one for malware
//     analysis)
//   - the "untrusted-apps" check in the DHIS2 audit (install-source
//     classification only — no per-app fetch)
export const fetchInstalledApps = async (engine) => {
    const response = await engine.query(APPS_QUERY)
    return Array.isArray(response.apps)
        ? response.apps
        : response.apps?.apps || []
}
