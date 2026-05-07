import { escapeHtml } from './html'

describe('escapeHtml', () => {
    it('escapes the standard HTML metacharacters', () => {
        expect(escapeHtml('<script>alert("xss")</script>')).toBe(
            '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
        )
    })

    it('escapes ampersands first to avoid double-encoding', () => {
        expect(escapeHtml('Tom & Jerry')).toBe('Tom &amp; Jerry')
        expect(escapeHtml('Already &amp; encoded')).toBe(
            'Already &amp;amp; encoded'
        )
    })

    it('escapes single quotes', () => {
        expect(escapeHtml("It's <fine>")).toBe('It&#39;s &lt;fine&gt;')
    })

    it('returns an empty string for null and undefined', () => {
        expect(escapeHtml(null)).toBe('')
        expect(escapeHtml(undefined)).toBe('')
    })

    it('coerces non-strings to string before escaping', () => {
        expect(escapeHtml(42)).toBe('42')
        expect(escapeHtml(false)).toBe('false')
    })

    it('returns plain text untouched', () => {
        expect(escapeHtml('hello world')).toBe('hello world')
    })
})
