import {
    BASELINE_RESOURCE,
    is404,
    loadBaselineDocument,
    saveBaselineDocument,
} from './baselineStore'

const notFound = () =>
    Object.assign(new Error('Not found'), {
        details: { httpStatusCode: 404 },
    })

describe('is404', () => {
    it('recognises both shapes the app runtime produces', () => {
        expect(is404(notFound())).toBe(true)
        expect(is404(new Error('HTTP 404 for dataStore/...'))).toBe(true)
        expect(is404(new Error('Forbidden'))).toBe(false)
        expect(is404(undefined)).toBe(false)
    })

    it('does not treat an unrelated number as a 404', () => {
        expect(is404(new Error('read 4045 rows'))).toBe(false)
    })
})

describe('loadBaselineDocument', () => {
    it('returns the stored document', async () => {
        const engine = { query: jest.fn(async () => ({ baseline: { apps: {} } })) }
        await expect(loadBaselineDocument(engine)).resolves.toEqual({
            baseline: { apps: {} },
        })
        expect(engine.query).toHaveBeenCalledWith({
            baseline: { resource: BASELINE_RESOURCE },
        })
    })

    it('treats a missing key as "no baseline yet", not an error', async () => {
        // The normal state before the first save. Surfacing it as an error
        // would put a red box in front of every first-time user.
        const engine = { query: jest.fn(async () => Promise.reject(notFound())) }
        await expect(loadBaselineDocument(engine)).resolves.toEqual({
            baseline: null,
        })
    })

    it('reports a real failure', async () => {
        const engine = {
            query: jest.fn(async () => Promise.reject(new Error('Forbidden'))),
        }
        const result = await loadBaselineDocument(engine)
        expect(result.baseline).toBeNull()
        expect(result.error).toMatch(/Forbidden/)
    })
})

describe('saveBaselineDocument', () => {
    it('updates an existing key', async () => {
        const engine = { mutate: jest.fn(async () => ({})) }
        await expect(saveBaselineDocument(engine, { apps: {} })).resolves.toEqual({
            success: true,
        })
        expect(engine.mutate).toHaveBeenCalledTimes(1)
        expect(engine.mutate.mock.calls[0][0].type).toBe('update')
    })

    it('creates the key on first save, when update 404s', async () => {
        // Every instance takes this path exactly once. DHIS2 answers 404 to
        // an update against a key that was never created.
        const engine = {
            mutate: jest.fn(async ({ type }) => {
                if (type === 'update') {
                    throw notFound()
                }
                return {}
            }),
        }
        await expect(saveBaselineDocument(engine, { apps: {} })).resolves.toEqual({
            success: true,
        })
        expect(engine.mutate.mock.calls.map((c) => c[0].type)).toEqual([
            'update',
            'create',
        ])
    })

    it('does not retry as create when update fails for another reason', async () => {
        // A permissions failure must surface, not be masked by a second
        // request that fails the same way.
        const engine = {
            mutate: jest.fn(async () => {
                throw new Error('Forbidden')
            }),
        }
        const result = await saveBaselineDocument(engine, { apps: {} })
        expect(result.success).toBe(false)
        expect(result.error).toMatch(/Forbidden/)
        expect(engine.mutate).toHaveBeenCalledTimes(1)
    })

    it('reports a failed create rather than throwing', async () => {
        const engine = {
            mutate: jest.fn(async ({ type }) => {
                throw type === 'update' ? notFound() : new Error('Disk full')
            }),
        }
        const result = await saveBaselineDocument(engine, { apps: {} })
        expect(result.success).toBe(false)
        expect(result.error).toMatch(/Disk full/)
    })
})
