import {
    findEndpoints,
    findSinks,
    isAllowedHost,
    normalizeHost,
    originHost,
    schemeFlags,
    sinkLabel,
    summarizeExternalEndpoints,
} from './externalEndpoints'

const hosts = (source) => findEndpoints(source).map((e) => e.host)

describe('findEndpoints', () => {
    it('finds a plain absolute URL', () => {
        expect(hosts('fetch("https://evil.example.net/collect")')).toEqual([
            'evil.example.net',
        ])
    })

    // Each of these is a different way of writing the same host. All of them
    // must reduce to one finding — that is what makes the check resistant to
    // the escaping a bundler or an obfuscator applies.
    it.each([
        ['JSON-escaped slashes', 'fetch("https:\\/\\/evil.example.net/x")'],
        ['unicode escapes', 'fetch("https://evil\\u002eexample\\u002enet/x")'],
        ['hex escapes', 'fetch("https:\\x2f\\x2fevil.example.net/x")'],
        ['percent-encoded', 'fetch("https:%2F%2Fevil.example.net/x")'],
        ['literal concatenation', 'fetch("https://evil."+"example.net/x")'],
        ['embedded credentials', 'fetch("https://dhis2.org:pw@evil.example.net/x")'],
        ['uppercase and trailing dot', 'fetch("https://EVIL.Example.NET./x")'],
        ['explicit port', 'fetch("https://evil.example.net:8443/x")'],
        ['protocol-relative', 'new WebSocket("//evil.example.net/ws")'],
    ])('normalizes %s to the bare host', (_label, source) => {
        expect(hosts(source)).toEqual(['evil.example.net'])
    })

    it('collapses repeats of one host into a single entry with a count', () => {
        const [entry] = findEndpoints(
            'a("https://evil.example.net/1");b("https://evil.example.net/2")'
        )
        expect(entry).toMatchObject({ host: 'evil.example.net', count: 2 })
    })

    it('flags a hardcoded IP address', () => {
        expect(findEndpoints('fetch("http://203.0.113.9/x")')[0]).toMatchObject({
            host: '203.0.113.9',
            ip: true,
        })
    })

    it('flags a punycode host, which reads as ASCII but is not', () => {
        expect(findEndpoints('fetch("https://xn--dhs2-5na.org/x")')[0]).toMatchObject(
            { host: 'xn--dhs2-5na.org', punycode: true }
        )
    })

    it('records the literal form it matched, not just the normalized host', () => {
        const [entry] = findEndpoints('fetch("https://EVIL.Example.NET./x")')
        expect(entry.samples[0]).toContain('EVIL.Example.NET')
    })

    // Every one of these appears in real bundles. Matching any of them would
    // make the check unusable long before it caught anything.
    it.each([
        ['a line comment', '// see foo.js for details\nvar a = 1'],
        ['a sourcemap reference', '//# sourceMappingURL=main.js.map'],
        ['chained division', 'var r = a.b/c.d/e.f'],
        ['a version string', 'var v = "1.2.3"'],
        ['a same-origin path', 'fetch("/api/apps/foo/index.html")'],
        ['a relative import', 'import("./chunk-a1b2.js")'],
    ])('does not match %s', (_label, source) => {
        expect(findEndpoints(source)).toEqual([])
    })
})

describe('scheme labels', () => {
    const label = (source) => {
        const [entry] = findEndpoints(source)
        return { schemes: entry.schemes, ...schemeFlags(entry.schemes) }
    }

    it('treats https as secure — no label', () => {
        expect(label('fetch("https://a.example.net/x")')).toMatchObject({
            cleartext: false,
            nonStandard: false,
        })
    })

    it('treats wss as secure — no label', () => {
        expect(label('new WebSocket("wss://a.example.net/x")')).toMatchObject({
            cleartext: false,
            nonStandard: false,
        })
    })

    it.each(['http', 'ws'])('labels %s:// as unencrypted', (scheme) => {
        expect(label(`fetch("${scheme}://a.example.net/x")`)).toMatchObject({
            schemes: [scheme],
            cleartext: true,
            nonStandard: false,
        })
    })

    it.each(['ftp', 'file', 'telnet', 'myapp'])(
        'labels %s:// as a non-standard protocol',
        (scheme) => {
            expect(label(`go("${scheme}://a.example.net/x")`)).toMatchObject({
                schemes: [scheme],
                cleartext: false,
                nonStandard: true,
            })
        }
    )

    // These have no //authority, so they are not destinations and must not
    // reach the finding list at all. data: in particular appears hundreds of
    // times in any bundle carrying inline SVG icons.
    it.each([
        ['data', 'src="data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="'],
        ['blob', 'URL.createObjectURL(b)//blob:https://x'],
        ['javascript', 'a.href="javascript:void(0)"'],
    ])('ignores the authority-less %s: scheme', (_name, source) => {
        expect(findEndpoints(source)).toEqual([])
    })

    it('unions schemes for one host seen over both http and https', () => {
        const summary = summarizeExternalEndpoints(
            [
                {
                    src: 'a.js',
                    sinks: [],
                    endpoints: findEndpoints('x("https://a.example.net/1")'),
                },
                {
                    src: 'b.js',
                    sinks: [],
                    endpoints: findEndpoints('x("http://a.example.net/2")'),
                },
            ],
            { instanceHost: 'dhis.example.org' }
        )
        expect(summary.hosts[0]).toMatchObject({
            host: 'a.example.net',
            cleartext: true,
        })
        expect(summary.hosts[0].schemes.sort()).toEqual(['http', 'https'])
    })
})

describe('normalizeHost', () => {
    it('keeps an IPv6 literal intact rather than truncating at its colons', () => {
        expect(normalizeHost('[2001:db8::1]:8443')).toBe('[2001:db8::1]')
    })

    it('takes the host after the last @, not the first', () => {
        expect(normalizeHost('a@b@real.example.net')).toBe('real.example.net')
    })
})

describe('findSinks', () => {
    it.each([
        ['fetch', 'fetch("/x")'],
        ['xhr', 'new XMLHttpRequest()'],
        ['websocket', 'new WebSocket("/ws")'],
        ['beacon', 'navigator.sendBeacon("/x", d)'],
        ['eventsource', 'new EventSource("/x")'],
        ['importscripts', 'importScripts("/x.js")'],
        ['serviceworker', 'navigator.serviceWorker.register("/sw.js")'],
        ['script-injection', 'document.createElement("script")'],
        ['webrtc', 'new RTCPeerConnection(cfg)'],
    ])('detects %s', (id, source) => {
        expect(findSinks(source)).toContain(id)
    })

    it('reports nothing for code that cannot open a connection', () => {
        expect(findSinks('const a = 1 + 2')).toEqual([])
    })

    it('labels sinks with their API name', () => {
        expect(sinkLabel('beacon')).toBe('navigator.sendBeacon()')
    })
})

describe('isAllowedHost', () => {
    it('allows the SVG namespace, which is an identifier and never fetched', () => {
        expect(isAllowedHost('www.w3.org')).toBe(true)
    })

    it('does not allow a CDN — loading code from one is the finding', () => {
        expect(isAllowedHost('cdn.jsdelivr.net')).toBe(false)
        expect(isAllowedHost('unpkg.com')).toBe(false)
    })

    it('allows loopback, which is a development leftover not a destination', () => {
        expect(isAllowedHost('localhost')).toBe(true)
        expect(isAllowedHost('127.0.0.1')).toBe(true)
    })

    it('supports a caller-supplied suffix allowlist', () => {
        expect(isAllowedHost('tiles.internal.example', ['.internal.example'])).toBe(
            true
        )
    })
})

describe('summarizeExternalEndpoints', () => {
    const file = (src, hostNames, sinks = []) => ({
        src,
        sinks,
        endpoints: hostNames.map((host) => ({
            host,
            count: 1,
            samples: [`https://${host}/x`],
            schemes: ['https'],
            ip: false,
            punycode: false,
        })),
    })

    it('ignores the instanceitself — that is every app talking to its server', () => {
        const summary = summarizeExternalEndpoints(
            [file('main.js', ['dhis.example.org'], ['fetch'])],
            { instanceHost: 'dhis.example.org' }
        )
        expect(summary).toMatchObject({ status: 'pass', hosts: [] })
    })

    it('warns when a host shares a file with a connection API', () => {
        const summary = summarizeExternalEndpoints(
            [file('main.js', ['evil.example.net'], ['fetch'])],
            { instanceHost: 'dhis.example.org' }
        )
        expect(summary.status).toBe('warning')
        expect(summary.reachableCount).toBe(1)
        expect(summary.hosts[0]).toMatchObject({
            host: 'evil.example.net',
            reachable: true,
        })
    })

    // The measured false positive: this app's own bundle puts 101 advisory
    // URLs in a data chunk that contains no connection API at all, while the
    // code chunk that does have fetch() carries only documentation links.
    // Correlating per app would call that "101 reachable hosts".
    it('reports a data blob with no connection API as an observation', () => {
        const summary = summarizeExternalEndpoints(
            [
                file('advisories.js', ['nvd.nist.gov', 'snyk.io']),
                file('main.js', [], ['fetch', 'xhr']),
            ],
            { instanceHost: 'dhis.example.org' }
        )
        expect(summary.status).toBe('info')
        expect(summary.reachableCount).toBe(0)
        expect(summary.sinks).toEqual(['fetch', 'xhr'])
    })

    it('sorts reachable hosts ahead of inert ones', () => {
        const summary = summarizeExternalEndpoints(
            [
                file('data.js', ['inert.example.net']),
                file('main.js', ['live.example.net'], ['fetch']),
            ],
            { instanceHost: 'dhis.example.org' }
        )
        expect(summary.hosts.map((h) => h.host)).toEqual([
            'live.example.net',
            'inert.example.net',
        ])
    })

    it('merges one host seen across several files', () => {
        const summary = summarizeExternalEndpoints(
            [
                file('a.js', ['evil.example.net']),
                file('b.js', ['evil.example.net'], ['fetch']),
            ],
            { instanceHost: 'dhis.example.org' }
        )
        expect(summary.hosts).toHaveLength(1)
        expect(summary.hosts[0]).toMatchObject({
            count: 2,
            reachable: true,
            files: ['a.js', 'b.js'],
        })
    })

    it('passes when there is nothing outside the instance', () => {
        expect(
            summarizeExternalEndpoints([file('main.js', [], ['fetch'])], {
                instanceHost: 'dhis.example.org',
            })
        ).toMatchObject({ status: 'pass', hosts: [] })
    })

    it('survives a result with no files', () => {
        expect(summarizeExternalEndpoints(undefined, {})).toMatchObject({
            status: 'pass',
            hosts: [],
        })
    })
})

describe('originHost', () => {
    it('extracts the hostname from an instance URL', () => {
        expect(originHost('https://play.dhis2.org/dhis/api/apps/x/index.html')).toBe(
            'play.dhis2.org'
        )
    })

    it('returns null for something that is not a URL', () => {
        expect(originHost('not a url')).toBeNull()
    })
})
