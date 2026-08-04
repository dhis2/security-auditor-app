// Fetch every page of a paginated DHIS2 resource, returning the flattened
// list of entries.
//
// `query` is a single-resource query in the @dhis2/app-runtime format, e.g.
//   { resource: 'users', params: { fields: 'id,username', filter: '...' } }
// The resource key is used to extract the entries array from each response.
//
// Returns the concatenated array of entries. Throws if `maxPages` is exceeded
// (defensive — should never trip in practice).
export const fetchAllPaged = async (
    engine,
    query,
    { pageSize = 200, maxPages = 1000 } = {}
) => {
    const resourceName = query.resource.split('/').pop()
    const queryKey = '__page'
    const all = []

    let page = 1
    let pageCount = 1
    while (page <= pageCount) {
        if (page > maxPages) {
            throw new Error(
                `fetchAllPaged exceeded maxPages (${maxPages}) for resource ${query.resource}`
            )
        }

        const response = await engine.query({
            [queryKey]: {
                ...query,
                params: {
                    ...query.params,
                    pageSize,
                    page,
                },
            },
        })

        const data = response[queryKey] || {}
        const entries = data[resourceName] || []
        all.push(...entries)

        // Stop if the response did not return a pager (single-page resource).
        if (!data.pager || typeof data.pager.pageCount !== 'number') {
            break
        }
        pageCount = data.pager.pageCount
        page += 1
    }

    return all
}
