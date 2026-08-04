import { fileStatus, appStatus } from './classifyFindings'

describe('fileStatus', () => {
    it('returns pass for empty warnings', () => {
        expect(fileStatus([])).toBe('pass')
        expect(fileStatus(undefined)).toBe('pass')
    })

    it('escalates to fail on obfuscation/unsafe-import/unsafe-stmt', () => {
        expect(fileStatus([{ kind: 'obfuscated-code' }])).toBe('fail')
        expect(fileStatus([{ kind: 'unsafe-import' }])).toBe('fail')
        expect(fileStatus([{ kind: 'unsafe-stmt' }])).toBe('fail')
    })

    it('warns on encoded literals, weak crypto, suspicious literals, parser errors', () => {
        expect(fileStatus([{ kind: 'encoded-literal' }])).toBe('warning')
        expect(fileStatus([{ kind: 'weak-crypto' }])).toBe('warning')
        expect(fileStatus([{ kind: 'suspicious-literal' }])).toBe('warning')
        expect(fileStatus([{ kind: 'parsing-error' }])).toBe('warning')
    })

    it('treats short-identifiers as info (no status bump)', () => {
        expect(fileStatus([{ kind: 'short-identifiers' }])).toBe('pass')
    })

    it('takes the strongest signal across multiple warnings', () => {
        expect(
            fileStatus([
                { kind: 'short-identifiers' },
                { kind: 'encoded-literal' },
                { kind: 'unsafe-import' },
            ])
        ).toBe('fail')
    })

    it('treats unknown warning kinds as warning, not silent pass', () => {
        expect(fileStatus([{ kind: 'something-future' }])).toBe('warning')
    })
})

describe('appStatus', () => {
    it('returns pass when no files reported issues', () => {
        expect(
            appStatus([{ src: 'a.js', warnings: [] }, { src: 'b.js', warnings: [] }])
        ).toBe('pass')
    })

    it('escalates to fail when any file fails', () => {
        expect(
            appStatus([
                { src: 'a.js', warnings: [{ kind: 'short-identifiers' }] },
                { src: 'b.js', warnings: [{ kind: 'obfuscated-code' }] },
            ])
        ).toBe('fail')
    })

    it('reports error if any file errored during fetch/analyze', () => {
        expect(
            appStatus([
                { src: 'a.js', warnings: [] },
                { src: 'b.js', error: 'Fetch failed' },
            ])
        ).toBe('error')
    })
})
