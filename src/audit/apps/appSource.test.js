import { appSource, APP_SOURCE } from './appSource'

describe('appSource', () => {
    it('reports app-hub when appHubId is present', () => {
        expect(appSource({ key: 'a', appHubId: 'abc-123' })).toBe(
            APP_SOURCE.APP_HUB
        )
    })

    it('reports manual when appHubId is absent', () => {
        expect(appSource({ key: 'a' })).toBe(APP_SOURCE.MANUAL)
        expect(appSource({ key: 'a', appHubId: null })).toBe(APP_SOURCE.MANUAL)
        expect(appSource({ key: 'a', appHubId: '' })).toBe(APP_SOURCE.MANUAL)
    })

    it('handles missing app object', () => {
        expect(appSource(null)).toBe(APP_SOURCE.MANUAL)
        expect(appSource(undefined)).toBe(APP_SOURCE.MANUAL)
    })
})
