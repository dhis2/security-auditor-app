import i18n from '@dhis2/d2-i18n'
import { APP_SOURCE, appSource } from '../apps/appSource'
import { fetchInstalledApps } from '../apps/fetchInstalledApps'

const SAMPLE_LIMIT = 10

// Quick install-source classification of every installed app. Flags any app
// not bundled with DHIS2 and not installed from App Hub as a warning, since
// sideloaded zips have no upstream signing/review and are the natural vector
// for malware. The Apps Audit then performs JS-X-Ray analysis on every app
// regardless of source — this check is the lightweight signal.
export const getAppSourceChecks = () => [
    {
        id: 'untrusted-app-sources',
        title: i18n.t('Installed App Sources'),
        description: i18n.t(
            'Checks whether any installed apps come from outside the App Hub or DHIS2 bundle'
        ),
        ranking: 0,
        fetch: (engine) => fetchInstalledApps(engine),
        evaluate: (apps) => {
            if (!apps || apps.length === 0) {
                return {
                    status: 'pass',
                    message: i18n.t('No installed apps detected'),
                }
            }

            const manual = apps.filter(
                (a) => appSource(a) === APP_SOURCE.MANUAL
            )

            if (manual.length === 0) {
                return {
                    status: 'pass',
                    message: i18n.t(
                        'All {{count}} installed apps come from bundled or App Hub sources',
                        { count: apps.length }
                    ),
                }
            }

            const sample = manual
                .slice(0, SAMPLE_LIMIT)
                .map((a) => `${a.name || a.key} (${a.key})`)
                .join(', ')
            const more = manual.length - SAMPLE_LIMIT

            return {
                status: 'warning',
                message: i18n.t(
                    '{{manualCount}} of {{total}} installed app(s) are from outside the App Hub',
                    { manualCount: manual.length, total: apps.length }
                ),
                details:
                    more > 0
                        ? i18n.t(
                              'Manually installed apps — {{sample}} and {{more}} more. Run the Apps Audit for malware analysis.',
                              { sample, more }
                          )
                        : i18n.t(
                              'Manually installed apps — {{sample}}. Run the Apps Audit for malware analysis.',
                              { sample }
                          ),
            }
        },
        onError: (error) => ({
            status: 'error',
            message: i18n.t('Could not fetch installed apps'),
            details: error?.message || String(error),
        }),
    },
]
