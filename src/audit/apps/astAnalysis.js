// One AST pass over a file, producing the two facts the endpoint check needs
// that regex cannot supply: where the connection calls actually are, and what
// role each string literal plays.
//
// The parser is injected rather than imported. The worker builds in `iife`
// format, which Vite cannot code-split, so it must import meriyah statically;
// the main-thread fallback wants it lazily so a 140 KB parser does not sit in
// the app bundle for a scan that may never run. Taking `parse` as an argument
// lets both paths share this code exactly, which is the property that keeps
// worker and fallback results identical.
//
// Everything here degrades to null rather than throwing. A file that will not
// parse still gets the regex analysis, which is what the check did before.

// Callee names that open a connection. Matched as *calls*, which is the whole
// point: `\bfetch\s*\(` also matches the word inside a string, a property
// named fetch, and a comment. Measured on DHIS2 2.43.1, the Data Entry
// app-wrapper chunk reports fetch/XMLHttpRequest by regex and contains zero
// actual sink calls.
const CALL_SINKS = new Map([
    ['fetch', 'fetch'],
    ['XMLHttpRequest', 'xhr'],
    ['WebSocket', 'websocket'],
    ['sendBeacon', 'beacon'],
    ['EventSource', 'eventsource'],
    ['importScripts', 'importscripts'],
    ['RTCPeerConnection', 'webrtc'],
])

// `open` is deliberately absent above: in real bundles it is overwhelmingly
// indexedDB.open() and document.open(). XMLHttpRequest is caught at
// construction instead, which is unambiguous.

const isServiceWorkerRegister = (callee) =>
    callee?.type === 'MemberExpression' &&
    callee.property?.name === 'register' &&
    callee.object?.property?.name === 'serviceWorker'

const isScriptCreation = (node, callee) =>
    callee?.type === 'MemberExpression' &&
    callee.property?.name === 'createElement' &&
    node.arguments?.[0]?.type === 'Literal' &&
    String(node.arguments[0].value).toLowerCase() === 'script'

const calleeName = (callee) => {
    if (!callee) {
        return null
    }
    if (callee.type === 'Identifier') {
        return callee.name
    }
    if (callee.type === 'MemberExpression' && callee.property?.type === 'Identifier') {
        return callee.property.name
    }
    return null
}

// Depth-first walk. Written by hand rather than pulled from a walker library:
// the shape is trivial, and this runs inside the worker where every added
// dependency is another copy in a bundle that already carries the analyzer.
const FUNCTION_TYPES = new Set([
    'FunctionDeclaration',
    'FunctionExpression',
    'ArrowFunctionExpression',
])

const walk = (node, visit, parent, fn) => {
    if (!node || typeof node !== 'object') {
        return
    }
    if (Array.isArray(node)) {
        for (const child of node) {
            walk(child, visit, parent, fn)
        }
        return
    }
    if (typeof node.type === 'string') {
        visit(node, parent, fn)
        if (FUNCTION_TYPES.has(node.type)) {
            fn = node
        }
        parent = node
    }
    for (const key of Object.keys(node)) {
        if (key !== 'type' && key !== 'loc' && key !== 'range') {
            walk(node[key], visit, parent, fn)
        }
    }
}

// Does this function ever assign a `.src`, and to what?
//
// A script element that is never given a src loads nothing. That is not a
// hypothetical: all four createElement("script") calls in DHIS2's Maintenance
// bundle are the setImmediate polyfill, which creates a script element purely
// to schedule a callback, and two of them are feature detection that never
// even keeps the element. Reporting those as a capability to load remote code
// is simply wrong.
//
// When a src *is* assigned a literal, that is the answer to "what does it
// open" — so it is captured rather than merely counted.
const srcAssignmentIn = (fn) => {
    let found = null
    walk(fn, (node) => {
        if (found) {
            return
        }
        if (
            node.type === 'AssignmentExpression' &&
            node.left?.type === 'MemberExpression' &&
            node.left.property?.name === 'src'
        ) {
            found = {
                url:
                    node.right?.type === 'Literal' &&
                    typeof node.right.value === 'string'
                        ? node.right.value
                        : null,
            }
        }
    })
    return found
}

// What a string literal is being used for. Only the distinctions that change
// how a URL should be read are made; everything else is `other`.
const literalRole = (node, parent) => {
    if (!parent) {
        return 'other'
    }
    if (
        (parent.type === 'CallExpression' || parent.type === 'NewExpression') &&
        parent.arguments?.includes(node)
    ) {
        return 'call-argument'
    }
    if (parent.type === 'Property' && parent.value === node) {
        return 'property-value'
    }
    if (parent.type === 'ArrayExpression') {
        return 'array-element'
    }
    if (
        parent.type === 'AssignmentExpression' &&
        parent.right === node
    ) {
        return 'assigned'
    }
    return 'other'
}

const nodeStart = (node) => node.start ?? node.range?.[0] ?? null

// Parse and collect. Returns null when the file cannot be parsed, so callers
// fall back rather than losing the file entirely.
//
// `parse` is called as parse(source) and must return an ESTree-shaped AST with
// node start offsets.
export const analyzeSource = (source, parse) => {
    if (typeof source !== 'string' || typeof parse !== 'function') {
        return null
    }
    let ast
    try {
        ast = parse(source)
    } catch {
        return null
    }

    const sinkCalls = []
    const literals = []
    const pendingScriptTags = []

    walk(ast, (node, parent, fn) => {
        if (node.type === 'CallExpression' || node.type === 'NewExpression') {
            const callee = node.callee
            const id =
                CALL_SINKS.get(calleeName(callee)) ||
                (isServiceWorkerRegister(callee) ? 'serviceworker' : null) ||
                (isScriptCreation(node, callee) ? 'script-injection' : null)
            if (id === 'script-injection') {
                // Held back until we know whether the element is ever given a
                // src. Without one it cannot load anything.
                pendingScriptTags.push({ index: nodeStart(node) ?? 0, fn })
                return
            }
            if (id) {
                sinkCalls.push({ id, index: nodeStart(node) ?? 0 })
            }
            return
        }
        if (node.type === 'Literal' && typeof node.value === 'string') {
            literals.push({
                value: node.value,
                index: nodeStart(node) ?? 0,
                role: literalRole(node, parent),
            })
            return
        }
        if (node.type === 'TemplateElement' && node.value?.cooked) {
            // A template's static parts are addresses just as much as a plain
            // literal is — `https://x/${id}` begins with one.
            literals.push({
                value: node.value.cooked,
                index: nodeStart(node) ?? 0,
                role: 'template',
            })
        }
    })

    // A created script element only counts once something assigns its src.
    const scriptSources = []
    for (const tag of pendingScriptTags) {
        // Falls back to the whole program: a script tag created at top level
        // has no enclosing function, and would otherwise never count.
        const assignment = srcAssignmentIn(tag.fn || ast)
        if (!assignment) {
            continue
        }
        sinkCalls.push({ id: 'script-injection', index: tag.index })
        if (assignment.url) {
            scriptSources.push({ url: assignment.url, index: tag.index })
        }
    }

    sinkCalls.sort((a, b) => a.index - b.index)
    return { sinkCalls, literals, scriptSources }
}
