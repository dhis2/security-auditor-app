import { findScripts, findModulePreloads, findEntryAssets } from './findScripts'

describe('findScripts', () => {
    it('returns an empty array for missing or non-string input', () => {
        expect(findScripts()).toEqual([])
        expect(findScripts(null)).toEqual([])
        expect(findScripts(123)).toEqual([])
    })

    it('preserves the script src as written (relative or absolute)', () => {
        // The caller resolves these via new URL(src, base), so we keep the
        // raw form. Stripping leading slashes would break root-absolute
        // srcs used by DHIS2 v42's unified app shell.
        const html = `
            <html><head>
              <script src="assets/main.js"></script>
              <script src="./vendor.js"></script>
              <script src="/sub/path.js"></script>
            </head></html>
        `
        expect(findScripts(html)).toEqual([
            'assets/main.js',
            './vendor.js',
            '/sub/path.js',
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

describe('findModulePreloads', () => {
    it('returns modulepreload hrefs', () => {
        const html = `
            <link rel="modulepreload" crossorigin href="./assets/index-DJAhnldu.js">
            <link rel="stylesheet" href="./assets/index.css">
            <link rel="icon" href="./favicon.ico">
        `
        expect(findModulePreloads(html)).toEqual(['./assets/index-DJAhnldu.js'])
    })

    it('matches rel as a token list, not an exact value', () => {
        const html = `<link rel="preload modulepreload" href="./a.js">`
        expect(findModulePreloads(html)).toEqual(['./a.js'])
    })

    it('applies the same cross-origin filter as scripts', () => {
        const html = `
            <link rel="modulepreload" href="https://cdn.example.com/a.js">
            <link rel="modulepreload" href="./b.js">
        `
        expect(findModulePreloads(html)).toEqual(['./b.js'])
    })
})

describe('findEntryAssets', () => {
    it('combines scripts and modulepreloads without duplicates', () => {
        // Shape emitted by Vite for the DHIS2 maps app: a ~1 KB entry stub
        // plus modulepreloads for the chunks holding the actual app code.
        const html = `
            <script type="module" crossorigin src="./assets/main-HBJjIm4U.js"></script>
            <link rel="modulepreload" crossorigin href="./assets/maps-gl-Do0JlnDk.js">
            <link rel="modulepreload" crossorigin href="./assets/index-DJAhnldu.js">
            <link rel="modulepreload" crossorigin href="./assets/main-HBJjIm4U.js">
        `
        expect(findEntryAssets(html)).toEqual([
            './assets/main-HBJjIm4U.js',
            './assets/maps-gl-Do0JlnDk.js',
            './assets/index-DJAhnldu.js',
        ])
    })

    it('returns an empty array for missing input', () => {
        expect(findEntryAssets()).toEqual([])
    })
})
