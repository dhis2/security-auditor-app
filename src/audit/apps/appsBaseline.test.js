import {
    INTEGRITY,
    baselineEntry,
    buildBaseline,
    compareEntry,
    describeIntegrity,
    fileHashes,
} from './appsBaseline'

const result = (key, version, files) => ({
    app: { key, version, name: key },
    files: Object.entries(files).map(([src, hash]) => ({ src, hash })),
})

describe('fileHashes', () => {
    it('collects only files that were actually hashed', () => {
        expect(
            fileHashes({
                files: [
                    { src: 'a.js', hash: 'aaa' },
                    { src: 'b.js', skipped: 'too large' },
                    { src: 'c.js', error: 'Fetch failed' },
                ],
            })
        ).toEqual({ 'a.js': 'aaa' })
    })

    it('tolerates a missing result', () => {
        expect(fileHashes(undefined)).toEqual({})
    })
})

describe('compareEntry', () => {
    const stored = { version: '1.0.0', files: { 'a.js': 'aaa', 'b.js': 'bbb' } }

    it('reports drift when content changes and the version does not', () => {
        // The finding this whole mechanism exists for.
        const cmp = compareEntry(
            result('app', '1.0.0', { 'a.js': 'aaa', 'b.js': 'MODIFIED' }),
            stored
        )
        expect(cmp.state).toBe(INTEGRITY.DRIFT)
        expect(cmp.changed).toEqual(['b.js'])
    })

    it('treats a version bump with changed content as a normal update', () => {
        const cmp = compareEntry(
            result('app', '1.1.0', { 'a.js': 'aaa', 'b.js': 'NEW' }),
            stored
        )
        expect(cmp.state).toBe(INTEGRITY.UPDATED)
    })

    it('reports unchanged when nothing moved', () => {
        expect(
            compareEntry(result('app', '1.0.0', { 'a.js': 'aaa', 'b.js': 'bbb' }), stored)
                .state
        ).toBe(INTEGRITY.UNCHANGED)
    })

    it('counts an added file at the same version as drift', () => {
        // A new chunk appearing without a release is how injected code shows
        // up when the original files are left untouched.
        const cmp = compareEntry(
            result('app', '1.0.0', { 'a.js': 'aaa', 'b.js': 'bbb', 'evil.js': 'xxx' }),
            stored
        )
        expect(cmp.state).toBe(INTEGRITY.DRIFT)
        expect(cmp.added).toEqual(['evil.js'])
    })

    it('counts a removed file at the same version as drift', () => {
        const cmp = compareEntry(result('app', '1.0.0', { 'a.js': 'aaa' }), stored)
        expect(cmp.state).toBe(INTEGRITY.DRIFT)
        expect(cmp.removed).toEqual(['b.js'])
    })

    it('reports new when there is no stored entry', () => {
        expect(compareEntry(result('app', '1.0.0', { 'a.js': 'aaa' }), null).state).toBe(
            INTEGRITY.NEW
        )
    })

    it('reports unknown when nothing could be hashed', () => {
        // Plain-HTTP instances have no Web Crypto. Claiming "unchanged"
        // there would be a lie: no comparison happened at all.
        expect(
            compareEntry({ app: { key: 'a' }, files: [{ src: 'a.js' }] }, stored).state
        ).toBe(INTEGRITY.UNKNOWN)
    })

    it('does not call an unhashable app new just because it has no baseline', () => {
        expect(compareEntry({ app: { key: 'a' }, files: [] }, null).state).toBe(
            INTEGRITY.UNKNOWN
        )
    })
})

describe('buildBaseline', () => {
    it('records hashes per app with metadata', () => {
        const doc = buildBaseline(
            [result('one', '1.0.0', { 'a.js': 'aaa' })],
            null,
            { recordedAt: '2026-08-04T00:00:00.000Z', systemId: 'sys-1' }
        )
        expect(doc.apps.one).toEqual({
            version: '1.0.0',
            name: 'one',
            files: { 'a.js': 'aaa' },
        })
        expect(doc.recordedAt).toBe('2026-08-04T00:00:00.000Z')
        expect(doc.systemId).toBe('sys-1')
        expect(doc.baselineVersion).toBe(1)
    })

    it('keeps the previous entry for an app that could not be scanned', () => {
        // A transient fetch failure or an expired session must not silently
        // erase a good baseline and reset that app to "new" next run.
        const previous = {
            apps: { one: { version: '1.0.0', files: { 'a.js': 'aaa' } } },
        }
        const doc = buildBaseline(
            [{ app: { key: 'one' }, files: [], notScanned: 'login-redirect' }],
            previous
        )
        expect(doc.apps.one.files).toEqual({ 'a.js': 'aaa' })
    })

    it('carries prior instance metadata forward when none is supplied', () => {
        const doc = buildBaseline([], { systemId: 'sys-1', dhis2Version: '2.43.1' })
        expect(doc.systemId).toBe('sys-1')
        expect(doc.dhis2Version).toBe('2.43.1')
    })
})

describe('baselineEntry', () => {
    it('stores nulls rather than undefined for a versionless app', () => {
        expect(baselineEntry({ app: { key: 'x' }, files: [] })).toEqual({
            version: null,
            name: null,
            files: {},
        })
    })
})
