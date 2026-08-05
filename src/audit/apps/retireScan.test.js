import {
    expandVersionPlaceholders,
    highestSeverity,
    isAtOrAbove,
    scanFile,
} from './retireScan'

// A miniature repository in the upstream shape, including the §§version§§
// placeholder so the expansion step is exercised the way the real file is.
const rawRepository = {
    components: {
        jquery: {
            npmname: 'jquery',
            extractors: {
                filename: ['jquery-(§§version§§)(\\.min)?\\.js'],
                filecontent: ['/\\*!? jQuery v(§§version§§)'],
                hashes: { abc123: '1.7.0' },
            },
            vulnerabilities: [
                {
                    below: '3.5.0',
                    severity: 'medium',
                    identifiers: {
                        CVE: ['CVE-2020-11022'],
                        summary: 'XSS in htmlPrefilter',
                    },
                },
                {
                    below: '1.9.0',
                    severity: 'high',
                    identifiers: { CVE: ['CVE-2012-6708'] },
                },
            ],
        },
        lodash: {
            extractors: {
                // The minified-code form: /pattern/replacement/
                filecontentreplace: [
                    '/VERSION *= *[\'"](§§version§§)[\'"]/$1/',
                ],
            },
            vulnerabilities: [
                { below: '4.18.0', severity: 'high', identifiers: { CVE: ['CVE-2021-23337'] } },
            ],
        },
    },
}

const repository = {
    ...rawRepository,
    components: expandVersionPlaceholders(rawRepository.components),
}

describe('expandVersionPlaceholders', () => {
    it('substitutes the version pattern everywhere it appears', () => {
        expect(repository.components.jquery.extractors.filename[0]).toBe(
            'jquery-([0-9][0-9.a-z_\\-]+)(\\.min)?\\.js'
        )
    })

    it('leaves non-string values alone', () => {
        expect(repository.components.jquery.extractors.hashes).toEqual({
            abc123: '1.7.0',
        })
    })
})

describe('isAtOrAbove', () => {
    it('compares numerically, not lexically', () => {
        // "10" must beat "9"; a string compare gets this wrong.
        expect(isAtOrAbove('1.10.0', '1.9.0')).toBe(true)
        expect(isAtOrAbove('1.9.0', '1.10.0')).toBe(false)
    })

    it('treats equal versions as at-or-above', () => {
        expect(isAtOrAbove('3.5.0', '3.5.0')).toBe(true)
    })

    it('pads missing segments with zero', () => {
        expect(isAtOrAbove('3.5', '3.5.0')).toBe(true)
        expect(isAtOrAbove('3.5.1', '3.5')).toBe(true)
    })

    it('ranks a numeric segment above a non-numeric one, as upstream does', () => {
        // 1.0.0 is a release; 1.0.0-beta precedes it.
        expect(isAtOrAbove('1.0.0', '1.0.0-beta')).toBe(true)
    })
})

describe('scanFile', () => {
    it('identifies a library from the file name and reports its CVEs', () => {
        const [found] = scanFile(
            { src: './vendor/jquery-3.3.1.min.js' },
            repository
        )
        expect(found.component).toBe('jquery')
        expect(found.version).toBe('3.3.1')
        expect(found.detection).toBe('filename')
        // 3.3.1 is below 3.5.0 but not below 1.9.0 — only one advisory applies.
        expect(found.vulnerabilities.map((v) => v.identifiers.CVE[0])).toEqual([
            'CVE-2020-11022',
        ])
    })

    it('identifies a library from a comment banner in the content', () => {
        const [found] = scanFile(
            { src: 'bundle.js', content: '/*! jQuery v3.6.0 | (c) OpenJS */' },
            repository
        )
        expect(found).toMatchObject({ component: 'jquery', version: '3.6.0' })
    })

    it('identifies a minified library via a replacement pattern', () => {
        // The case that matters: no comments survive minification, but the
        // version string does.
        const [found] = scanFile(
            { src: 'main-abc123.js', content: 'var x=1;VERSION="4.17.21";' },
            repository
        )
        expect(found).toMatchObject({
            component: 'lodash',
            version: '4.17.21',
            detection: 'filecontentreplace',
        })
        expect(found.vulnerabilities).toHaveLength(1)
    })

    it('reports a library with no applicable advisory as not vulnerable', () => {
        const [found] = scanFile(
            { src: 'main.js', content: 'VERSION="4.18.1";' },
            repository
        )
        expect(found.component).toBe('lodash')
        expect(found.vulnerabilities).toEqual([])
    })

    it('falls back to a file hash only when content matching finds nothing', () => {
        const viaHash = scanFile(
            { src: 'unknown.js', content: 'nothing recognisable', sha1: 'abc123' },
            repository
        )
        expect(viaHash[0]).toMatchObject({
            component: 'jquery',
            version: '1.7.0',
            detection: 'hash',
        })
    })

    it('does not consult the hash when the content already identified it', () => {
        const found = scanFile(
            {
                src: 'x.js',
                content: '/*! jQuery v3.6.0 */',
                sha1: 'abc123',
            },
            repository
        )
        expect(found).toHaveLength(1)
        expect(found[0].version).toBe('3.6.0')
    })

    it('de-duplicates a library found by more than one extractor', () => {
        const found = scanFile(
            {
                src: './jquery-3.6.0.js',
                content: '/*! jQuery v3.6.0 | (c) OpenJS */',
            },
            repository
        )
        expect(found).toHaveLength(1)
    })

    it('strips a .min suffix from the captured version, as upstream does', () => {
        const [found] = scanFile({ src: 'jquery-3.6.0.min.js' }, repository)
        expect(found.version).toBe('3.6.0')
    })

    it('anchors filename patterns to the last path segment', () => {
        // A directory that happens to look like a library must not match.
        expect(scanFile({ src: 'jquery-3.3.1.min.js/actually-a-dir.txt' }, repository))
            .toEqual([])
    })

    it('returns nothing without a repository', () => {
        expect(scanFile({ src: 'jquery-3.3.1.js' }, null)).toEqual([])
        expect(scanFile({ src: 'jquery-3.3.1.js' }, {})).toEqual([])
    })

    it('survives a malformed pattern instead of aborting the scan', () => {
        const broken = {
            components: {
                bad: { extractors: { filecontent: ['('] }, vulnerabilities: [] },
                ...repository.components,
            },
        }
        expect(() =>
            scanFile({ src: 'x.js', content: '/*! jQuery v3.6.0 */' }, broken)
        ).not.toThrow()
    })

    it('terminates on a pattern that can match the empty string', () => {
        // With the `g` flag a zero-length match leaves lastIndex unmoved and
        // exec() would loop forever. Upstream has no guard for this.
        const looping = {
            components: {
                loop: {
                    extractors: { filecontent: ['(x?)'] },
                    vulnerabilities: [],
                },
            },
        }
        expect(() => scanFile({ src: 'a.js', content: 'abc' }, looping)).not.toThrow()
    })
})

describe('highestSeverity', () => {
    it('returns the most severe across all detections', () => {
        expect(
            highestSeverity([
                { vulnerabilities: [{ severity: 'low' }, { severity: 'high' }] },
                { vulnerabilities: [{ severity: 'medium' }] },
            ])
        ).toBe('high')
    })

    it('returns null when nothing is vulnerable', () => {
        expect(highestSeverity([{ vulnerabilities: [] }])).toBeNull()
        expect(highestSeverity([])).toBeNull()
    })
})
