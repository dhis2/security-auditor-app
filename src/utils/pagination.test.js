import { fetchAllPaged } from './pagination'

const makeEngine = (pages) => {
    let callIndex = 0
    return {
        query: jest.fn(async () => {
            const response = pages[callIndex]
            callIndex += 1
            return response
        }),
    }
}

describe('fetchAllPaged', () => {
    it('returns the entries from a single-page response', async () => {
        const engine = makeEngine([
            {
                __page: {
                    users: [{ id: 'a' }, { id: 'b' }],
                    pager: { page: 1, pageCount: 1, total: 2 },
                },
            },
        ])
        const result = await fetchAllPaged(engine, {
            resource: 'users',
            params: { fields: 'id' },
        })
        expect(result).toEqual([{ id: 'a' }, { id: 'b' }])
        expect(engine.query).toHaveBeenCalledTimes(1)
    })

    it('concatenates entries across multiple pages', async () => {
        const engine = makeEngine([
            {
                __page: {
                    users: [{ id: 'a' }, { id: 'b' }],
                    pager: { page: 1, pageCount: 3, total: 6 },
                },
            },
            {
                __page: {
                    users: [{ id: 'c' }, { id: 'd' }],
                    pager: { page: 2, pageCount: 3, total: 6 },
                },
            },
            {
                __page: {
                    users: [{ id: 'e' }, { id: 'f' }],
                    pager: { page: 3, pageCount: 3, total: 6 },
                },
            },
        ])
        const result = await fetchAllPaged(engine, {
            resource: 'users',
            params: { fields: 'id' },
        })
        expect(result.map((u) => u.id)).toEqual(['a', 'b', 'c', 'd', 'e', 'f'])
        expect(engine.query).toHaveBeenCalledTimes(3)
    })

    it('passes pageSize and incrementing page to each query', async () => {
        const engine = makeEngine([
            {
                __page: {
                    users: [],
                    pager: { page: 1, pageCount: 2, total: 0 },
                },
            },
            {
                __page: {
                    users: [],
                    pager: { page: 2, pageCount: 2, total: 0 },
                },
            },
        ])
        await fetchAllPaged(
            engine,
            { resource: 'users', params: { fields: 'id' } },
            { pageSize: 50 }
        )
        const firstCall = engine.query.mock.calls[0][0].__page
        const secondCall = engine.query.mock.calls[1][0].__page
        expect(firstCall.params).toMatchObject({ pageSize: 50, page: 1, fields: 'id' })
        expect(secondCall.params).toMatchObject({ pageSize: 50, page: 2, fields: 'id' })
    })

    it('returns the single response when no pager is present', async () => {
        const engine = makeEngine([{ __page: { users: [{ id: 'a' }] } }])
        const result = await fetchAllPaged(engine, {
            resource: 'users',
            params: {},
        })
        expect(result).toEqual([{ id: 'a' }])
        expect(engine.query).toHaveBeenCalledTimes(1)
    })

    it('throws when maxPages is exceeded', async () => {
        // Server returns a wildly inconsistent pager that never terminates.
        const runawayEngine = {
            query: jest.fn(async () => ({
                __page: {
                    users: [],
                    pager: { page: 1, pageCount: 9999, total: 0 },
                },
            })),
        }
        await expect(
            fetchAllPaged(
                runawayEngine,
                { resource: 'users', params: {} },
                { maxPages: 3 }
            )
        ).rejects.toThrow(/exceeded maxPages/)
    })

    it('handles a missing entries array gracefully', async () => {
        const engine = makeEngine([
            { __page: { pager: { page: 1, pageCount: 1, total: 0 } } },
        ])
        const result = await fetchAllPaged(engine, {
            resource: 'users',
            params: {},
        })
        expect(result).toEqual([])
    })
})
