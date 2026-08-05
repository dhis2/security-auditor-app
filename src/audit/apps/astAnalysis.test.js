import { parseModule, parseScript } from 'meriyah'
import { analyzeSource } from './astAnalysis'

const parse = (source) => {
    try {
        return parseModule(source, { next: true })
    } catch {
        return parseScript(source, { next: true })
    }
}

const sinkIds = (source) =>
    [...new Set(analyzeSource(source, parse).sinkCalls.map((c) => c.id))].sort()

describe('analyzeSource — sinks', () => {
    it('finds a real call', () => {
        expect(sinkIds('fetch("/x")')).toEqual(['fetch'])
        expect(sinkIds('new WebSocket(u)')).toEqual(['websocket'])
        expect(sinkIds('new XMLHttpRequest()')).toEqual(['xhr'])
        expect(sinkIds('navigator.sendBeacon(u, d)')).toEqual(['beacon'])
        expect(sinkIds('navigator.serviceWorker.register("/sw.js")')).toEqual([
            'serviceworker',
        ])
        expect(sinkIds('document.createElement("script")')).toEqual([
            'script-injection',
        ])
    })

    it('does not count the word fetch inside a string', () => {
        // The regex check reports this file as having a connection API. It
        // does not: measured on DHIS2 2.43.1, the Data Entry app-wrapper
        // chunk claims fetch and XMLHttpRequest and contains no sink call.
        expect(sinkIds('const msg = "call fetch(url) to load"')).toEqual([])
    })

    it('does not count a property or method merely named fetch', () => {
        expect(sinkIds('const o = { fetch: 1 }; o.fetch')).toEqual([])
    })

    it('does not count indexedDB.open or document.open as network', () => {
        // In Capture's chunk almost every `open(` is one of these.
        expect(sinkIds('indexedDB.open(name); document.open()')).toEqual([])
    })

    it('does count a method call on an object, such as window.fetch', () => {
        expect(sinkIds('window.fetch("/x")')).toEqual(['fetch'])
    })

    it('only treats createElement("script") as injection', () => {
        expect(sinkIds('document.createElement("div")')).toEqual([])
    })
})

describe('analyzeSource — literals', () => {
    const roles = (source) =>
        analyzeSource(source, parse).literals.map((l) => [l.value, l.role])

    it('records the role a string is used in', () => {
        expect(roles('fetch("https://a.example.net")')).toContainEqual([
            'https://a.example.net',
            'call-argument',
        ])
        expect(roles('const o = { url: "https://b.example.net" }')).toContainEqual([
            'https://b.example.net',
            'property-value',
        ])
        expect(roles('const a = ["https://c.example.net"]')).toContainEqual([
            'https://c.example.net',
            'array-element',
        ])
    })

    it('records the static parts of a template', () => {
        expect(
            roles('const u = `https://d.example.net/${id}`').map(([v]) => v)
        ).toContain('https://d.example.net/')
    })

    it('gives the parser-decoded value, not the escaped source text', () => {
        // This is why literal *values* rather than offsets drive the address
        // decision: the parser decodes escapes exactly as the normalizer does.
        expect(
            roles('fetch("https:\\u002f\\u002fe.example.net/c")').map(([v]) => v)
        ).toContain('https://e.example.net/c')
    })
})

describe('analyzeSource — failure', () => {
    it('returns null for source that will not parse, rather than throwing', () => {
        // The caller falls back to the text analysis, so a file that cannot be
        // parsed is still examined.
        expect(analyzeSource('function (', parse)).toBeNull()
    })

    it('returns null without a parser', () => {
        expect(analyzeSource('fetch("/x")', null)).toBeNull()
    })
})
