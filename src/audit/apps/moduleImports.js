// Extract relative module specifiers referenced by a JavaScript module.
//
// Vite (which every modern DHIS2 app is built with) splits an app across many
// chunks. Only the entry chunk — and whatever the document happens to declare
// as <link rel="modulepreload"> — is reachable from index.html. Everything
// else is referenced from inside the JS itself, in one of these shapes:
//
//   import{a as b}from"./index-DJAhnldu.js"      static import
//   import"./maps-gl-Do0JlnDk.js"                side-effect import
//   import("./AppWrapper-DhJT2Ulb.js")           dynamic import
//   d=["./AppWrapper-DhJT2Ulb.js","./index.js"]  __vite__mapDeps table
//
// All four are ordinary string literals holding a relative path ending in
// .js/.mjs, so one literal scan catches every form. We deliberately do NOT
// parse the AST here: these files are 600+ KB of minified code and this runs
// on the browser main thread alongside the analyzer that already parses them.
//
// A literal scan can pick up strings that merely look like module paths and
// aren't fetchable. That is why the crawler treats a failed fetch of a
// *discovered* file as a skip rather than an error — a false path costs one
// 404, not a bogus finding.
const SPECIFIER = /(["'`])(\.{1,2}\/[^"'`\n\r]*?\.m?js)\1/g

export const findModuleImports = (source) => {
    if (!source || typeof source !== 'string') {
        return []
    }
    const out = new Set()
    // Reset lastIndex defensively — the regex is module-level and global.
    SPECIFIER.lastIndex = 0
    let match
    while ((match = SPECIFIER.exec(source)) !== null) {
        out.add(match[2])
    }
    return [...out]
}
