import {
    fetchApiMeHeaders,
    getServerHeader,
    __resetApiMeCache,
} from './instanceInfo'

const headers = (entries) => ({
    get: (name) => entries[name.toLowerCase()] ?? null,
})

beforeEach(() => {
    __resetApiMeCache()
    global.fetch = jest.fn()
})

describe('fetchApiMeHeaders', () => {
    it('shares one fetch across concurrent callers for the same contextPath', async () => {
        global.fetch.mockResolvedValue({ headers: headers({ server: 'nginx' }) })

        const [a, b] = await Promise.all([
            fetchApiMeHeaders('https://example.org/dhis'),
            fetchApiMeHeaders('https://example.org/dhis'),
        ])
        expect(a.get('server')).toBe('nginx')
        expect(b.get('server')).toBe('nginx')
        expect(global.fetch).toHaveBeenCalledTimes(1)
    })

    it('issues separate fetches for different contextPaths', async () => {
        global.fetch.mockImplementation((url) =>
            Promise.resolve({
                headers: headers({ server: url.includes('one') ? 'A' : 'B' }),
            })
        )

        const a = await fetchApiMeHeaders('https://one.example/dhis')
        const b = await fetchApiMeHeaders('https://two.example/dhis')

        expect(a.get('server')).toBe('A')
        expect(b.get('server')).toBe('B')
        expect(global.fetch).toHaveBeenCalledTimes(2)
        expect(global.fetch.mock.calls[0][0]).toBe('https://one.example/dhis/api/me')
        expect(global.fetch.mock.calls[1][0]).toBe('https://two.example/dhis/api/me')
    })

    it('falls back to a relative URL when contextPath is missing', async () => {
        global.fetch.mockResolvedValue({ headers: headers({}) })
        await fetchApiMeHeaders()
        expect(global.fetch.mock.calls[0][0]).toBe('../api/me')
    })

    it('clears the cache on failure so a later call can retry', async () => {
        global.fetch
            .mockRejectedValueOnce(new Error('network'))
            .mockResolvedValueOnce({ headers: headers({ server: 'nginx' }) })

        await expect(fetchApiMeHeaders('https://x.example/dhis')).rejects.toThrow(
            'network'
        )
        const second = await fetchApiMeHeaders('https://x.example/dhis')
        expect(second.get('server')).toBe('nginx')
        expect(global.fetch).toHaveBeenCalledTimes(2)
    })

    it('caches successes so a later call does NOT refetch', async () => {
        global.fetch.mockResolvedValueOnce({
            headers: headers({ server: 'nginx' }),
        })
        await fetchApiMeHeaders('https://x.example/dhis')
        await fetchApiMeHeaders('https://x.example/dhis')
        expect(global.fetch).toHaveBeenCalledTimes(1)
    })
})

describe('getServerHeader', () => {
    it('returns the value of the server header on success', async () => {
        global.fetch.mockResolvedValue({
            headers: headers({ server: 'nginx/1.20' }),
        })
        const value = await getServerHeader('https://x.example/dhis')
        expect(value).toBe('nginx/1.20')
    })

    it('returns null on fetch failure (no throw)', async () => {
        global.fetch.mockRejectedValue(new Error('boom'))
        const value = await getServerHeader('https://x.example/dhis')
        expect(value).toBeNull()
    })

    it('returns null when the server header is missing', async () => {
        global.fetch.mockResolvedValue({ headers: headers({}) })
        const value = await getServerHeader('https://x.example/dhis')
        expect(value).toBeNull()
    })
})
