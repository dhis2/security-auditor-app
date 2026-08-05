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

describe('the allowlist admits only hosts nobody else can publish to', () => {
    // The condition that matters. A code-hosting or package host is exactly
    // where a payload would be fetched from, so allow-listing one would hide
    // the single case this check exists to catch.
    it.each([
        'github.com',
        'raw.githubusercontent.com',
        'gist.githubusercontent.com',
        'registry.npmjs.org',
        'www.npmjs.com',
        'attacker.github.io',
        'jedwatson.github.io',
        'stackoverflow.com',
        'sodipodi.sourceforge.net',
        'fb.me',
        'cra.link',
        'apps.dhis2.org',
    ])('does not allow %s', (host) => {
        expect(isAllowedHost(host)).toBe(false)
    })

    it.each([
        'www.w3.org',
        'schema.org',
        'purl.org',
        'reactjs.org',
        'docs.dhis2.org',
    ])('allows %s, which appears as an address and is not publishable', (host) => {
        expect(isAllowedHost(host)).toBe(true)
    })

    it('still honours hosts an administrator adds explicitly', () => {
        expect(isAllowedHost('cdn.example.org', ['cdn.example.org'])).toBe(true)
    })
})

describe('proximity to a connection call', () => {
    it('treats a URL beside a call as reachable', () => {
        const [entry] = findEndpoints('fetch("https://api.example.net/x")')
        expect(entry.nearSink).toBe(true)
    })

    it('does not call a distant URL reachable just for sharing the file', () => {
        // The Capture case: one 6.5 MB chunk, three connection calls, and a
        // Leaflet marker PNG 10 KB away from the nearest of them. Per file
        // that read as "reachable from code that opens connections".
        const source =
            'fetch("https://api.example.net/x");' +
            'x'.repeat(50000) +
            'const icon="https://cdn.example.net/marker.png"'
        const hosts = Object.fromEntries(
            findEndpoints(source).map((e) => [e.host, e.nearSink])
        )
        expect(hosts['api.example.net']).toBe(true)
        expect(hosts['cdn.example.net']).toBe(false)
    })

    it('honours a configured window', () => {
        const source =
            'fetch("https://api.example.net/x")' +
            'y'.repeat(3000) +
            'const u="https://far.example.net/y"'
        expect(
            findEndpoints(source, { proximityChars: 10000 }).find(
                (e) => e.host === 'far.example.net'
            ).nearSink
        ).toBe(true)
    })
})

describe('reserved names that can never resolve', () => {
    it.each([
        'query-string.invalid',
        'foo.test',
        'bar.example',
        'thing.localhost',
        'example.com',
        'www.example.org',
    ])('ignores %s', (host) => {
        expect(findEndpoints(`u("https://${host}/x")`)).toEqual([])
    })

    it('still reports a real host with a similar name', () => {
        expect(
            findEndpoints('u("https://invalid-example.net/x")').map((e) => e.host)
        ).toEqual(['invalid-example.net'])
    })
})

describe('addresses versus prose mentions', () => {
    const hostsOf = (source) => findEndpoints(source).map((e) => e.host)

    it('counts a URL that begins its literal as an address', () => {
        const [entry] = findEndpoints('fetch("https://api.example.net/x")')
        expect(entry.addressCount).toBe(1)
    })

    it('counts a URL quoted inside a sentence as a mention, not an address', () => {
        // Verbatim from the Temporal polyfill in DHIS2's Data Entry app,
        // which cites four Chromium bug reports in its RangeError text.
        const source =
            'throw new RangeError(`Invalid month ${m} (probably due to https://bugs.chromium.org/p/v8/issues/detail?id=10527)`)'
        const [entry] = findEndpoints(source)
        expect(entry.host).toBe('bugs.chromium.org')
        expect(entry.count).toBe(1)
        expect(entry.addressCount).toBe(0)
    })

    it('treats a template literal as an address', () => {
        expect(
            findEndpoints('const u = `https://api.example.net/${id}`')[0]
                .addressCount
        ).toBe(1)
    })

    it('treats a split-up literal as an address once folded', () => {
        // Splitting a URL across concatenated literals is how it gets hidden
        // from a reader grepping the bundle; folding happens before matching,
        // so the result still begins its literal.
        const [entry] = findEndpoints('const u = "https://api" + ".example.net/x"')
        expect(entry.host).toBe('api.example.net')
        expect(entry.addressCount).toBe(1)
    })

    it('still records the host, so it can be counted rather than lost', () => {
        expect(hostsOf('// see https://docs.example.net for details')).toEqual([
            'docs.example.net',
        ])
    })

    it('excludes a prose-only host from the summary but reports the count', () => {
        const summary = summarizeExternalEndpoints(
            [
                {
                    src: 'main.js',
                    sinks: ['fetch'],
                    endpoints: findEndpoints(
                        'throw new Error(`see https://bugs.chromium.org/x`)'
                    ),
                },
            ],
            { instanceHost: 'dhis.example.org' }
        )
        expect(summary.hosts).toEqual([])
        expect(summary.mentionedOnlyCount).toBe(1)
        // Named, not just counted: a bare count asks the reader to trust the
        // classifier rather than check it.
        // Carries the URL as written, not just the host name.
        expect(summary.mentionedOnly).toEqual([
            expect.objectContaining({
                host: 'bugs.chromium.org',
                sample: expect.stringContaining('bugs.chromium.org/x'),
            }),
        ])
        // Nothing addressable, so nothing to warn about.
        expect(summary.status).toBe('pass')
    })

    it('keeps a host that is used as an address somewhere, even if also mentioned', () => {
        const summary = summarizeExternalEndpoints(
            [
                {
                    src: 'a.js',
                    sinks: [],
                    endpoints: findEndpoints('`see https://x.example.net/doc`'),
                },
                {
                    src: 'b.js',
                    sinks: ['fetch'],
                    endpoints: findEndpoints('fetch("https://x.example.net/api")'),
                },
            ],
            { instanceHost: 'dhis.example.org' }
        )
        expect(summary.hosts.map((h) => h.host)).toEqual(['x.example.net'])
        expect(summary.mentionedOnlyCount).toBe(0)
        expect(summary.mentionedOnly).toEqual([])
        expect(summary.status).toBe('warning')
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
    // `nearSink` mirrors what findEndpoints computes: the URL sits within the
    // proximity window of a connection call. Tests that pass sinks mean "and
    // the URL is beside one".
    const file = (src, hostNames, sinks = []) => ({
        src,
        sinks,
        endpoints: hostNames.map((host) => ({
            host,
            count: 1,
            nearSink: sinks.length > 0,
            // Used as an address, i.e. the URL begins its string literal.
            // Hosts named only inside prose are excluded from the summary.
            addressCount: 1,
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

    it('warns when a host sits beside a connection call', () => {
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
