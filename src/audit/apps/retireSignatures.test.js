import {
    SIGNATURES_RESOURCE,
    fetchLatestSignatures,
    isStale,
    loadStoredSignatures,
    saveStoredSignatures,
} from './retireSignatures'

const upstream = {
    advisories: {
        'retire-example': {
            extractors: { filecontent: ['example'] },
            vulnerabilities: [],
        },
        jquery: {
            npmname: 'jquery',
            extractors: {
                filename: ['jquery-(§§version§§)\\.js'],
                func: ['window.jQuery.fn.jquery'],
                ast: ['//AssignmentExpression'],
            },
            vulnerabilities: [{ below: '3.5.0', severity: 'medium' }],
        },
        'runtime-only': {
            // Nothing this scanner can evaluate against a fetched file.
            extractors: { func: ['window.thing.version'] },
            vulnerabilities: [{ below: '1.0.0' }],
        },
    },
}

const okResponse = (body) => ({ ok: true, json: async () => body })

describe('fetchLatestSignatures', () => {
    it('keeps only the extractors this scanner can evaluate', async () => {
        const result = await fetchLatestSignatures({
            fetchImpl: async () => okResponse(upstream),
            now: () => new Date('2026-08-05T10:00:00.000Z'),
        })
        expect(Object.keys(result.components)).toEqual(['jquery'])
        expect(Object.keys(result.components.jquery.extractors)).toEqual([
            'filename',
        ])
        expect(result.retrievedAt).toBe('2026-08-05T10:00:00.000Z')
    })

    it('drops the upstream self-test entry', async () => {
        const result = await fetchLatestSignatures({
            fetchImpl: async () => okResponse(upstream),
        })
        expect(result.components['retire-example']).toBeUndefined()
    })

    it('preserves the version placeholder for the loader to expand', async () => {
        const result = await fetchLatestSignatures({
            fetchImpl: async () => okResponse(upstream),
        })
        expect(result.components.jquery.extractors.filename[0]).toContain(
            '§§version§§'
        )
    })

    it('rejects a non-OK response', async () => {
        await expect(
            fetchLatestSignatures({
                fetchImpl: async () => ({ ok: false, status: 503 }),
            })
        ).rejects.toThrow(/503/)
    })

    it('rejects data that yields no usable components', async () => {
        // An error page or a redirect body that happens to parse as JSON
        // would otherwise be stored as an empty signature set, and every
        // subsequent scan would report everything clean.
        await expect(
            fetchLatestSignatures({
                fetchImpl: async () => okResponse({ message: 'Not Found' }),
            })
        ).rejects.toThrow(/not usable/)
    })

    it('accepts a bare advisories object as well as a wrapped one', async () => {
        const result = await fetchLatestSignatures({
            fetchImpl: async () => okResponse(upstream.advisories),
        })
        expect(result.components.jquery).toBeDefined()
    })
})

describe('isStale', () => {
    const now = Date.parse('2026-08-05T12:00:00.000Z')

    it('is false inside the window', () => {
        expect(isStale('2026-08-05T11:30:00.000Z', 60, now)).toBe(false)
    })

    it('is true past the window', () => {
        expect(isStale('2026-08-05T10:30:00.000Z', 60, now)).toBe(true)
    })

    it('treats a missing or unparseable timestamp as stale', () => {
        // Offering a refresh is the safe answer when the age is unknown.
        expect(isStale(undefined, 60, now)).toBe(true)
        expect(isStale('not a date', 60, now)).toBe(true)
    })

    it('accepts the date-only form the vendored copy records', () => {
        expect(isStale('2026-08-05', 60, Date.parse('2026-08-05T00:30:00Z'))).toBe(
            false
        )
    })
})

describe('loadStoredSignatures', () => {
    it('returns the stored document', async () => {
        const engine = {
            query: jest.fn(async () => ({ signatures: { components: {} } })),
        }
        await expect(loadStoredSignatures(engine)).resolves.toEqual({
            signatures: { components: {} },
        })
        expect(engine.query).toHaveBeenCalledWith({
            signatures: { resource: SIGNATURES_RESOURCE },
        })
    })

    it('treats a missing key as "never downloaded"', async () => {
        const engine = {
            query: async () => {
                throw Object.assign(new Error('nope'), {
                    details: { httpStatusCode: 404 },
                })
            },
        }
        await expect(loadStoredSignatures(engine)).resolves.toEqual({
            signatures: null,
        })
    })
})

describe('saveStoredSignatures', () => {
    it('creates the key when update 404s', async () => {
        const engine = {
            mutate: jest.fn(async ({ type }) => {
                if (type === 'update') {
                    throw Object.assign(new Error('nope'), {
                        details: { httpStatusCode: 404 },
                    })
                }
                return {}
            }),
        }
        await expect(saveStoredSignatures(engine, {})).resolves.toEqual({
            success: true,
        })
        expect(engine.mutate.mock.calls.map((c) => c[0].type)).toEqual([
            'update',
            'create',
        ])
    })

    it('reports a permissions failure instead of throwing', async () => {
        const engine = {
            mutate: async () => {
                throw new Error('Forbidden')
            },
        }
        const result = await saveStoredSignatures(engine, {})
        expect(result).toEqual({ success: false, error: 'Forbidden' })
    })
})
