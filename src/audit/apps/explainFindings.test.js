import {
    explainWarning,
    hasRiskWarnings,
    isRiskKind,
} from './explainFindings'

describe('explainWarning', () => {
    it('distinguishes eval from the Function constructor', () => {
        // Both arrive as `unsafe-stmt`, but they warrant different readings:
        // one is a real eval call, the other the globalThis shim every bundle
        // carries. Reporting them identically is what made the finding
        // useless.
        const evalCase = explainWarning({ kind: 'unsafe-stmt', value: 'eval' })
        const fnCase = explainWarning({ kind: 'unsafe-stmt', value: 'Function' })
        expect(evalCase.title).toMatch(/eval/i)
        expect(evalCase.detail).toMatch(/ExtJS|OpenLayers|MapLibre/)
        expect(fnCase.title).toMatch(/Function constructor/i)
        expect(fnCase.detail).toMatch(/return this/)
        expect(evalCase.title).not.toBe(fnCase.title)
    })

    it('explains minification without repeating the raw score', () => {
        const explained = explainWarning({
            kind: 'short-identifiers',
            value: 1.4173309575166464,
        })
        expect(explained.title).toMatch(/minified/i)
        expect(explained.detail).not.toContain('1.417')
    })

    it('names the obfuscator it matched', () => {
        expect(
            explainWarning({ kind: 'obfuscated-code', value: 'jsfuck' }).detail
        ).toContain('jsfuck')
    })

    it('covers every kind the classifier can produce', () => {
        // A kind with no explanation falls back to the bare name, which is
        // the state this module exists to remove.
        for (const kind of [
            'short-identifiers',
            'unsafe-stmt',
            'encoded-literal',
            'suspicious-literal',
            'parsing-error',
            'obfuscated-code',
            'unsafe-import',
            'weak-crypto',
        ]) {
            const explained = explainWarning({ kind })
            expect(explained).not.toBeNull()
            expect(explained.title.length).toBeGreaterThan(0)
            expect(explained.detail.length).toBeGreaterThan(0)
        }
    })

    it('returns null for an unknown kind rather than inventing an answer', () => {
        expect(explainWarning({ kind: 'something-future' })).toBeNull()
        expect(explainWarning(undefined)).toBeNull()
    })
})

describe('isRiskKind', () => {
    it('treats build artefacts as not a risk', () => {
        // These are the kinds every minified production bundle emits.
        expect(isRiskKind('short-identifiers')).toBe(false)
        expect(isRiskKind('unsafe-stmt')).toBe(false)
        expect(isRiskKind('encoded-literal')).toBe(false)
        expect(isRiskKind('parsing-error')).toBe(false)
    })

    it('treats the rare kinds as a risk', () => {
        expect(isRiskKind('obfuscated-code')).toBe(true)
        expect(isRiskKind('unsafe-import')).toBe(true)
        expect(isRiskKind('weak-crypto')).toBe(true)
        expect(isRiskKind('suspicious-literal')).toBe(true)
    })
})

describe('hasRiskWarnings', () => {
    it('is false for a file that only reports build artefacts', () => {
        expect(
            hasRiskWarnings([
                { kind: 'unsafe-stmt', value: 'eval' },
                { kind: 'short-identifiers', value: 1.07 },
            ])
        ).toBe(false)
    })

    it('is true when any warning is a risk kind', () => {
        expect(
            hasRiskWarnings([
                { kind: 'short-identifiers' },
                { kind: 'obfuscated-code' },
            ])
        ).toBe(true)
    })

    it('tolerates missing input', () => {
        expect(hasRiskWarnings(undefined)).toBe(false)
        expect(hasRiskWarnings([])).toBe(false)
    })
})
