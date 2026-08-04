import { appSource, APP_SOURCE } from './appSource'

describe('appSource', () => {
    it('reports bundled when bundled flag is true', () => {
        expect(appSource({ key: 'a', bundled: true })).toBe(APP_SOURCE.BUNDLED)
    })

    it('reports bundled when legacy coreApp flag is true', () => {
        expect(appSource({ key: 'a', coreApp: true })).toBe(APP_SOURCE.BUNDLED)
    })

    it('prefers bundled over appHubId during version transitions', () => {
        expect(appSource({ key: 'a', bundled: true, appHubId: 'x' })).toBe(
            APP_SOURCE.BUNDLED
        )
    })

    it('reports app-hub when appHubId is present and not bundled', () => {
        expect(appSource({ key: 'a', appHubId: 'abc-123' })).toBe(
            APP_SOURCE.APP_HUB
        )
    })

    it('reports manual when neither bundled nor appHubId is set', () => {
        expect(appSource({ key: 'a' })).toBe(APP_SOURCE.MANUAL)
        expect(appSource({ key: 'a', appHubId: null })).toBe(APP_SOURCE.MANUAL)
        expect(appSource({ key: 'a', appHubId: '' })).toBe(APP_SOURCE.MANUAL)
        expect(appSource({ key: 'a', bundled: false })).toBe(APP_SOURCE.MANUAL)
    })

    it('handles missing app object', () => {
        expect(appSource(null)).toBe(APP_SOURCE.MANUAL)
        expect(appSource(undefined)).toBe(APP_SOURCE.MANUAL)
    })
})
