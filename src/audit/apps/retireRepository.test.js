import {
    __setVendoredRepositoryForTests,
    getRetireRepository,
} from './retireRepository'

const vendored = {
    retrievedAt: '2026-08-01',
    source: 'bundled-source',
    components: {
        jquery: {
            extractors: { filename: ['jquery-(§§version§§)\\.js'] },
            vulnerabilities: [],
        },
    },
}

const downloaded = (retrievedAt) => ({
    retrievedAt,
    source: 'downloaded-source',
    components: {
        lodash: {
            extractors: { filecontent: ['lodash (§§version§§)'] },
            vulnerabilities: [],
        },
    },
})

beforeEach(() => __setVendoredRepositoryForTests(vendored))
afterEach(() => __setVendoredRepositoryForTests(null))

describe('getRetireRepository', () => {
    it('uses the vendored copy when nothing has been downloaded', async () => {
        const repo = await getRetireRepository()
        expect(repo.origin).toBe('bundled')
        expect(Object.keys(repo.components)).toEqual(['jquery'])
    })

    it('prefers a newer downloaded set', async () => {
        const repo = await getRetireRepository({
            stored: downloaded('2026-08-05T10:00:00.000Z'),
        })
        expect(repo.origin).toBe('downloaded')
        expect(Object.keys(repo.components)).toEqual(['lodash'])
    })

    it('falls back to the vendored copy when the download is older', async () => {
        // After an app upgrade the bundled data can be newer than whatever
        // was downloaded months ago; the stale download must not shadow it.
        const repo = await getRetireRepository({
            stored: downloaded('2026-07-01T10:00:00.000Z'),
        })
        expect(repo.origin).toBe('bundled')
    })

    it('ignores a stored document with no components', async () => {
        const repo = await getRetireRepository({
            stored: { retrievedAt: '2027-01-01T00:00:00.000Z' },
        })
        expect(repo.origin).toBe('bundled')
    })

    it('ignores a stored document with an unusable timestamp', async () => {
        const repo = await getRetireRepository({
            stored: { ...downloaded('nonsense') },
        })
        expect(repo.origin).toBe('bundled')
    })

    it('expands version placeholders in whichever source wins', async () => {
        const repo = await getRetireRepository({
            stored: downloaded('2026-08-05T10:00:00.000Z'),
        })
        expect(repo.components.lodash.extractors.filecontent[0]).toBe(
            'lodash ([0-9][0-9.a-z_\\-]+)'
        )
    })
})
