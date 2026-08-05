import {
    SEVERITY_ORDER,
    buildFindingSections,
    groupWarnings,
    severityLabel,
} from './groupFindings'

const lib = (component, version, vulns) => ({
    src: 'main.js',
    warnings: [],
    libraries: [
        {
            component,
            version,
            vulnerabilities: vulns,
        },
    ],
})

describe('buildFindingSections', () => {
    it('orders sections worst first', () => {
        const files = [
            lib('moment.js', '2.29.1', [
                { severity: 'high', identifiers: { CVE: ['CVE-2022-24785'] } },
                { severity: 'medium', identifiers: { CVE: ['CVE-X'] } },
                { severity: 'low', identifiers: { CVE: ['CVE-Y'] } },
            ]),
        ]
        expect(buildFindingSections(files).map((s) => s.severity)).toEqual([
            'high',
            'medium',
            'low',
        ])
    })

    it('labels each group with its subject', () => {
        const [section] = buildFindingSections([
            lib('moment.js', '2.29.1', [
                { severity: 'high', identifiers: { CVE: ['CVE-2022-24785'] } },
            ]),
        ])
        expect(section.label).toBe('HIGH')
        expect(section.groups[0].subject).toBe('moment.js 2.29.1')
    })

    it('puts one library into several sections when its advisories differ', () => {
        // lodash 4.17.21 carries both medium and high advisories. Filing them
        // all under the worst would overstate the medium ones and hide which
        // is which.
        const sections = buildFindingSections([
            lib('lodash', '4.17.21', [
                { severity: 'medium', identifiers: { CVE: ['CVE-2025-13465'] } },
                { severity: 'high', identifiers: { CVE: ['CVE-2021-23337'] } },
            ]),
        ])
        expect(sections.map((s) => s.severity)).toEqual(['high', 'medium'])
        expect(sections[0].groups[0].subject).toBe('lodash 4.17.21')
        expect(sections[1].groups[0].subject).toBe('lodash 4.17.21')
    })

    it('states the fixed-in version, which is the actionable part', () => {
        const [section] = buildFindingSections([
            lib('moment.js', '2.29.1', [
                {
                    severity: 'high',
                    below: '2.29.2',
                    identifiers: {
                        CVE: ['CVE-2022-24785'],
                        summary: 'Path traversal in locale',
                    },
                },
            ]),
        ])
        const [item] = section.groups[0].items
        expect(item.title).toBe('CVE-2022-24785')
        expect(item.detail).toContain('Path traversal in locale')
        expect(item.detail).toContain('Fixed in 2.29.2')
    })

    it('files code findings by severity alongside library advisories', () => {
        const sections = buildFindingSections([
            {
                src: './main.js',
                warnings: [
                    { kind: 'obfuscated-code', value: 'jsfuck' },
                    { kind: 'short-identifiers', value: 1.4 },
                ],
                libraries: [],
            },
        ])
        expect(sections.map((s) => s.severity)).toEqual(['high', 'info'])
        expect(sections[0].groups[0].subject).toBe('./main.js')
        expect(sections[0].groups[0].items[0].title).toMatch(/obfuscator/i)
        expect(sections[1].groups[0].items[0].title).toBe('Minified code')
    })

    it('collapses repeated findings into one row with a count', () => {
        const [section] = buildFindingSections([
            {
                src: 'ext-all.js',
                warnings: Array(5).fill({ kind: 'unsafe-stmt', value: 'eval' }),
                libraries: [],
            },
        ])
        expect(section.groups[0].items).toHaveLength(1)
        expect(section.groups[0].items[0].title).toBe('Uses eval() (5x)')
    })

    it('keeps unexamined files in their own section, last', () => {
        const sections = buildFindingSections([
            lib('lodash', '4.17.21', [{ severity: 'high', identifiers: {} }]),
            {
                src: './App-x.js',
                error: 'Analyzer failed: …',
                incomplete: true,
                libraries: [],
            },
        ])
        expect(sections.map((s) => s.severity)).toEqual(['high', 'unexamined'])
        const last = sections[sections.length - 1]
        expect(last.label).toBe('NOT EXAMINED')
        expect(last.groups[0].items[0].title).toMatch(/Analyzer failed/)
    })

    it('returns nothing for an app with no findings at all', () => {
        expect(
            buildFindingSections([{ src: 'a.js', warnings: [], libraries: [] }])
        ).toEqual([])
        expect(buildFindingSections([])).toEqual([])
        expect(buildFindingSections(undefined)).toEqual([])
    })
})

describe('groupWarnings', () => {
    it('counts identical findings and keeps distinct ones apart', () => {
        const grouped = groupWarnings([
            { kind: 'unsafe-stmt', value: 'eval' },
            { kind: 'unsafe-stmt', value: 'eval' },
            { kind: 'unsafe-stmt', value: 'Function' },
        ])
        expect(grouped).toHaveLength(2)
        expect(grouped[0].count).toBe(2)
        expect(grouped[1].count).toBe(1)
    })
})

describe('severityLabel', () => {
    it('labels every section severity', () => {
        for (const severity of SEVERITY_ORDER) {
            expect(severityLabel(severity)).not.toBe('UNKNOWN')
        }
    })
})

describe('external endpoint findings', () => {
    const external = (host) => ({
        hosts: [host],
        sinks: ['fetch'],
        reachableCount: host.reachable ? 1 : 0,
        status: host.reachable ? 'warning' : 'info',
    })
    const base = {
        host: 'tracker.example.net',
        count: 2,
        samples: ['https://tracker.example.net/c'],
        schemes: ['https'],
        files: ['main.js'],
        reachable: true,
        ip: false,
        punycode: false,
        cleartext: false,
        nonStandard: false,
    }
    const titleFor = (host) => {
        const sections = buildFindingSections([], { external: external(host) })
        return sections[0].groups[0].items[0].title
    }

    it('puts a reachable host in a severity section, not in info', () => {
        const [section] = buildFindingSections([], { external: external(base) })
        expect(section.severity).toBe('medium')
        expect(section.groups[0].subject).toBe('External connections')
    })

    it('reports an unreachable host as an observation', () => {
        const [section] = buildFindingSections([], {
            external: external({ ...base, reachable: false }),
        })
        expect(section.severity).toBe('info')
    })

    it('labels an unencrypted host with the scheme responsible', () => {
        const title = titleFor({
            ...base,
            schemes: ['http'],
            cleartext: true,
        })
        expect(title).toContain('unencrypted (http)')
    })

    it('labels a non-standard protocol with the scheme responsible', () => {
        const title = titleFor({
            ...base,
            schemes: ['ftp'],
            nonStandard: true,
        })
        expect(title).toContain('non-standard protocol (ftp)')
    })

    it('names only the offending scheme when a host was seen over several', () => {
        const title = titleFor({
            ...base,
            schemes: ['https', 'http'],
            cleartext: true,
        })
        expect(title).toContain('unencrypted (http)')
        expect(title).not.toContain('https')
    })

    it('stacks every applicable label on one host', () => {
        const title = titleFor({
            ...base,
            host: '203.0.113.9',
            schemes: ['http'],
            cleartext: true,
            ip: true,
        })
        expect(title).toContain('reachable')
        expect(title).toContain('unencrypted (http)')
        expect(title).toContain('hardcoded IP address')
    })

    it('names the connection APIs as their own item', () => {
        const [section] = buildFindingSections([], { external: external(base) })
        const titles = section.groups[0].items.map((i) => i.title)
        expect(titles).toContain('Connection APIs present in this app')
    })
})

describe('mention-only hosts', () => {
    it('names them rather than only counting them', () => {
        const [section] = buildFindingSections([], {
            external: {
                hosts: [],
                sinks: [],
                mentionedOnly: ['bugs.chromium.org', 'momentjs.com'],
                mentionedOnlyCount: 2,
            },
        })
        const [item] = section.groups[0].items
        expect(section.severity).toBe('info')
        expect(item.title).toContain('2')
        expect(item.detail).toContain('bugs.chromium.org')
        expect(item.detail).toContain('momentjs.com')
    })

    it('says nothing when every host was used as an address', () => {
        expect(
            buildFindingSections([], {
                external: { hosts: [], sinks: [], mentionedOnly: [], mentionedOnlyCount: 0 },
            })
        ).toEqual([])
    })
})
