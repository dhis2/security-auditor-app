// Derive an app's installation source from the /api/apps response.
//
// DHIS2 distinguishes three sources:
//   - bundled: shipped with the DHIS2 platform itself (core/built-in apps).
//     Marked by `bundled: true` on v40+, or `coreApp: true` on older
//     instances. Bundled apps have no appHubId.
//   - app-hub: installed from apps.dhis2.org. Marked by a non-empty
//     `appHubId` (the App Hub listing identifier).
//   - manual: admin uploaded a .zip directly. No `appHubId`, not bundled.
//
// The signal isn't tamper-proof — a sideloaded app could fake `bundled` or
// `appHubId` in its manifest — but for typical operational use it's the
// right honest signal. Order matters: check bundled first because some
// bundled apps in transition versions may also carry an appHubId.
export const APP_SOURCE = {
    BUNDLED: 'bundled',
    APP_HUB: 'app-hub',
    MANUAL: 'manual',
}

export const appSource = (app) => {
    if (!app) {
        return APP_SOURCE.MANUAL
    }
    if (app.bundled || app.coreApp) {
        return APP_SOURCE.BUNDLED
    }
    return app.appHubId ? APP_SOURCE.APP_HUB : APP_SOURCE.MANUAL
}
