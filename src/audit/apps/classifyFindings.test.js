import {
    fileStatus,
    appStatus,
    resultStatus,
    suppressBenign,
} from './classifyFindings'

describe('fileStatus', () => {
    it('returns pass for empty warnings', () => {
        expect(fileStatus([])).toBe('pass')
        expect(fileStatus(undefined)).toBe('pass')
    })

    it('fails only on a positively fingerprinted obfuscator', () => {
        expect(fileStatus([{ kind: 'obfuscated-code' }])).toBe('fail')
    })

    it('warns on unsafe imports, weak crypto and suspicious literals', () => {
        expect(fileStatus([{ kind: 'unsafe-import' }])).toBe('warning')
        expect(fileStatus([{ kind: 'weak-crypto' }])).toBe('warning')
        expect(fileStatus([{ kind: 'suspicious-literal' }])).toBe('warning')
    })

    it('does not escalate the kinds every minified bundle produces', () => {
        // Measured on eight untouched DHIS2 2.43.1 production bundles: each
        // one emits unsafe-stmt x3, encoded-literal x1 and short-identifiers
        // from React/lodash/i18next vendor code alone. Escalating these made
        // all 45 apps on an instance FAIL.
        expect(fileStatus([{ kind: 'unsafe-stmt' }])).toBe('pass')
        expect(fileStatus([{ kind: 'encoded-literal' }])).toBe('pass')
        expect(fileStatus([{ kind: 'short-identifiers' }])).toBe('pass')
        expect(fileStatus([{ kind: 'parsing-error' }])).toBe('pass')
    })

    it('takes the strongest signal across multiple warnings', () => {
        expect(
            fileStatus([
                { kind: 'short-identifiers' },
                { kind: 'encoded-literal' },
                { kind: 'unsafe-import' },
            ])
        ).toBe('warning')
        expect(
            fileStatus([
                { kind: 'unsafe-import' },
                { kind: 'obfuscated-code' },
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

describe('resultStatus', () => {
    it('reports an app-level failure as error, not pass', () => {
        // Regression: these results carry no files, so they used to reach
        // appStatus([]) and an app whose index.html could not be fetched was
        // reported as clean.
        expect(resultStatus({ files: [], error: 'Network down' })).toBe('error')
    })

    it('reports an unscanned app as info, not pass', () => {
        expect(resultStatus({ files: [], notScanned: 'shell-redirect' })).toBe(
            'info'
        )
    })

    it('otherwise reduces the file results', () => {
        expect(
            resultStatus({ files: [{ warnings: [{ kind: 'obfuscated-code' }] }] })
        ).toBe('fail')
        expect(resultStatus({ files: [{ warnings: [] }] })).toBe('pass')
    })
})

describe('suppressBenign', () => {
    it('drops the globalThis shim that every bundle carries', () => {
        const source = 'var g=self||Function("return this")();'
        const warnings = [
            {
                kind: 'unsafe-stmt',
                value: 'Function',
                location: [1, source.indexOf('Function')],
            },
        ]
        expect(suppressBenign(warnings, source)).toEqual([])
    })

    it('keeps an unsafe-stmt that is not the shim', () => {
        const source = 'eval(atob(payload));'
        const warnings = [
            { kind: 'unsafe-stmt', value: 'eval', location: [1, 0] },
        ]
        expect(suppressBenign(warnings, source)).toHaveLength(1)
    })

    it('handles both js-x-ray location shapes', () => {
        const source = 'x=Function("return this")()'
        const nested = [
            {
                kind: 'unsafe-stmt',
                value: 'Function',
                location: [[1, 2], [1, 24]],
            },
        ]
        expect(suppressBenign(nested, source)).toEqual([])
    })

    it('drops short encoded literals but keeps decodable payloads', () => {
        // "added" is an i18next event name; "E7113" is a DHIS2 error code.
        // Both are reported as encoded-literal on live bundles.
        const long = 'aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ='
        expect(
            suppressBenign(
                [
                    { kind: 'encoded-literal', value: 'added' },
                    { kind: 'encoded-literal', value: 'E7113' },
                    { kind: 'encoded-literal', value: long },
                ],
                ''
            ).map((w) => w.value)
        ).toEqual([long])
    })

    it('suppresses nothing that needs a location when source is missing', () => {
        const warnings = [
            { kind: 'unsafe-stmt', value: 'Function', location: [1, 0] },
        ]
        expect(suppressBenign(warnings, undefined)).toHaveLength(1)
    })
})
