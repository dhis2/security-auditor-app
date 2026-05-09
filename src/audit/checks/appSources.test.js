import { getAppSourceChecks } from './appSources'

const findCheck = () =>
    getAppSourceChecks().find((c) => c.id === 'untrusted-app-sources')

describe('untrusted-app-sources check', () => {
    it('passes when no apps are installed', () => {
        const result = findCheck().evaluate([])
        expect(result.status).toBe('pass')
    })

    it('passes when every app is bundled or from App Hub', () => {
        const apps = [
            { key: 'a', bundled: true },
            { key: 'b', appHubId: 'abc' },
            { key: 'c', coreApp: true },
        ]
        const result = findCheck().evaluate(apps)
        expect(result.status).toBe('pass')
        expect(result.message).toMatch(/3/)
    })

    it('warns when at least one manually-installed app is present', () => {
        const apps = [
            { key: 'bundled-one', bundled: true },
            { key: 'manual-one', name: 'Manual One' },
        ]
        const result = findCheck().evaluate(apps)
        expect(result.status).toBe('warning')
        expect(result.message).toMatch(/1/)
        expect(result.message).toMatch(/2/)
        expect(result.details).toMatch(/Manual One/)
        expect(result.details).toMatch(/manual-one/)
    })

    it('truncates the sample list and reports the remaining count', () => {
        const apps = []
        for (let i = 0; i < 13; i++) {
            apps.push({ key: `m${i}`, name: `Manual ${i}` })
        }
        const result = findCheck().evaluate(apps)
        expect(result.status).toBe('warning')
        expect(result.details).toMatch(/and 3 more/)
    })

    it('reports an error if the apps endpoint cannot be fetched', () => {
        const override = findCheck().onError(new Error('forbidden'))
        expect(override.status).toBe('error')
        expect(override.details).toMatch(/forbidden/)
    })

    it('uses fetchInstalledApps via the runner fetch hook', () => {
        // The runner calls check.fetch(engine, ctx) and passes the result to
        // evaluate. The check just delegates to the shared helper.
        expect(typeof findCheck().fetch).toBe('function')
    })
})
