import { findScripts } from './findScripts'

describe('findScripts', () => {
    it('returns an empty array for missing or non-string input', () => {
        expect(findScripts()).toEqual([])
        expect(findScripts(null)).toEqual([])
        expect(findScripts(123)).toEqual([])
    })

    it('extracts relative <script src> entries', () => {
        const html = `
            <html><head>
              <script src="assets/main.js"></script>
              <script src="./vendor.js"></script>
              <script src="/sub/path.js"></script>
            </head></html>
        `
        expect(findScripts(html)).toEqual([
            'assets/main.js',
            'vendor.js',
            'sub/path.js',
        ])
    })

    it('skips remote scripts (cross-origin can\'t be analyzed)', () => {
        const html = `
            <script src="https://cdn.example.com/lib.js"></script>
            <script src="//other.example.com/lib.js"></script>
            <script src="local.js"></script>
        `
        expect(findScripts(html)).toEqual(['local.js'])
    })

    it('strips query strings and fragments', () => {
        const html = `<script src="main.js?v=42"></script><script src="other.js#frag"></script>`
        expect(findScripts(html)).toEqual(['main.js', 'other.js'])
    })

    it('ignores inline <script> blocks (no src attribute)', () => {
        const html = `
            <script>console.log('inline')</script>
            <script src="main.js"></script>
        `
        expect(findScripts(html)).toEqual(['main.js'])
    })
})
