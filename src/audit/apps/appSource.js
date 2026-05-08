// Derive an app's installation source from the /api/apps response.
//
// DHIS2 marks App-Hub-installed apps with an `appHubId` (the listing's
// identifier on apps.dhis2.org). Sideloaded apps (admin uploaded a .zip)
// have no appHubId. The signal isn't tamper-proof — a sideloaded app's
// manifest could fake the field — but for typical operational use it's
// the right honest signal.
export const APP_SOURCE = {
    APP_HUB: 'app-hub',
    MANUAL: 'manual',
}

export const appSource = (app) => {
    if (!app) {
        return APP_SOURCE.MANUAL
    }
    return app.appHubId ? APP_SOURCE.APP_HUB : APP_SOURCE.MANUAL
}
