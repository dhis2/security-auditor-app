import { findModuleImports } from './moduleImports'

describe('findModuleImports', () => {
    it('returns an empty array for missing or non-string input', () => {
        expect(findModuleImports()).toEqual([])
        expect(findModuleImports(null)).toEqual([])
        expect(findModuleImports(42)).toEqual([])
    })

    it('finds every specifier shape Vite emits', () => {
        // Verbatim shape of the DHIS2 maps app entry chunk.
        const source = `
            const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["./AppWrapper-DhJT2Ulb.js","./index-DJAhnldu.js"])))=>i.map(i=>d[i]);
            import{R as t,_ as p}from"./index-DJAhnldu.js";
            import"./maps-gl-Do0JlnDk.js";
            const d=t.lazy(()=>p(()=>import("./AppWrapper-DhJT2Ulb.js")));
        `
        expect(findModuleImports(source).sort()).toEqual([
            './AppWrapper-DhJT2Ulb.js',
            './index-DJAhnldu.js',
            './maps-gl-Do0JlnDk.js',
        ])
    })

    it('de-duplicates repeated specifiers', () => {
        const source = 'import"./a.js";import("./a.js");const x=["./a.js"]'
        expect(findModuleImports(source)).toEqual(['./a.js'])
    })

    it('handles single quotes, backticks and parent-relative paths', () => {
        const source = `import'./a.js';import(\`../shared/b.mjs\`)`
        expect(findModuleImports(source).sort()).toEqual([
            '../shared/b.mjs',
            './a.js',
        ])
    })

    it('ignores bare and absolute specifiers', () => {
        // Bare specifiers are already bundled; absolute URLs are cross-origin
        // and out of scope for the crawl.
        const source =
            'import"react";import"https://cdn.example.com/x.js";import"/root.js"'
        expect(findModuleImports(source)).toEqual([])
    })

    it('is reusable across calls (global regex lastIndex is reset)', () => {
        const source = 'import"./a.js"'
        expect(findModuleImports(source)).toEqual(['./a.js'])
        expect(findModuleImports(source)).toEqual(['./a.js'])
    })
})
