import i18n from '@dhis2/d2-i18n'
import '../../i18nConfig'

// Plain-language explanations for the code-analysis findings.
//
// These findings do not set a verdict — see the calibration note in
// classifyFindings.js for why heuristics over minified bundles cannot. But
// reporting "unsafe-stmt (Function)" and nothing else leaves a reader unable
// to tell whether they are looking at a problem. Every one of them needs to
// answer two questions: what triggered this, and does it matter.
//
// The honest answer for all of them, on the DHIS2 apps measured, is "a
// bundled third-party library, and no". Saying so explicitly is the point.

const EXPLANATIONS = {
    'short-identifiers': () => ({
        title: i18n.t('Minified code'),
        detail: i18n.t(
            'Identifier names in this file average about one character, which means it was minified. That is how every production JavaScript build is shipped. It describes how the file was compiled, not anything in it.'
        ),
    }),
    'unsafe-stmt': (value) =>
        value === 'eval'
            ? {
                  title: i18n.t('Uses eval()'),
                  detail: i18n.t(
                      'eval() runs a string as code. Several long-standing libraries use it internally — ExtJS, OpenLayers and MapLibre all do — so it is expected in a bundle that includes them. It is worth attention only if it appears in an app’s own code, or if the string being run could come from user input.'
                  ),
              }
            : {
                  title: i18n.t('References the Function constructor'),
                  detail: i18n.t(
                      'Bundled libraries use Function("return this") to locate the global object; lodash and most UMD wrappers contain it. The constructor is reported because it can also turn a string into code, but a fixed string like this one cannot be influenced by an attacker.'
                  ),
              },
    'encoded-literal': () => ({
        title: i18n.t('Long encoded-looking string'),
        detail: i18n.t(
            'A long run of hex or base64-like characters. In practice these are checksums, file-format signatures, or embedded assets such as icons. It would only matter if the string decoded to code that the app then ran.'
        ),
    }),
    'suspicious-literal': () => ({
        title: i18n.t('String assembled by concatenation'),
        detail: i18n.t(
            'The file builds strings by joining fragments, which is one way obfuscated code hides text. Minifiers and template libraries do the same thing for ordinary reasons.'
        ),
    }),
    'parsing-error': () => ({
        title: i18n.t('Could not be parsed'),
        detail: i18n.t(
            'The analyzer could not read this file, so it was not examined. This is usually newer JavaScript syntax the bundled analyzer does not support, not a problem with the file.'
        ),
    }),
    'obfuscated-code': (value) => ({
        title: i18n.t('Matches a known obfuscator'),
        detail: i18n.t(
            'The file carries the fingerprint of {{tool}}. Legitimate apps are minified, not obfuscated, so this is worth investigating.',
            { tool: value || i18n.t('a known obfuscation tool') }
        ),
    }),
    'unsafe-import': () => ({
        title: i18n.t('Loads code from a computed location'),
        detail: i18n.t(
            'The file imports a module whose address is built at runtime rather than written literally. Code splitting does this legitimately; so does code that fetches a payload from elsewhere.'
        ),
    }),
    'weak-crypto': () => ({
        title: i18n.t('Uses a weak hash'),
        detail: i18n.t(
            'MD5 or SHA-1 appears in this file. Both are unsuitable for signatures or passwords, though they remain common for non-security uses such as cache keys.'
        ),
    }),
}

// Kinds that describe a real problem rather than an artefact of how the file
// was built. Everything else is reported under a heading that says plainly
// that no risk was found.
const RISK_KINDS = new Set([
    'obfuscated-code',
    'unsafe-import',
    'weak-crypto',
    'suspicious-literal',
])

export const isRiskKind = (kind) => RISK_KINDS.has(kind)

// Severity band for a code-analysis finding, on the same scale the library
// advisories use, so both can be grouped into one set of sections.
//
// Only a positively fingerprinted obfuscator rates high; the other risk kinds
// are worth a look but are not conclusive on a minified bundle. Everything
// else describes how the file was built and is informational.
export const warningSeverity = (kind) => {
    if (kind === 'obfuscated-code') {
        return 'high'
    }
    return RISK_KINDS.has(kind) ? 'medium' : 'info'
}

// Returns { title, detail } for a warning, or null for a kind we have nothing
// useful to say about — better to show the raw kind than invent an
// explanation for it.
export const explainWarning = (warning) => {
    const build = EXPLANATIONS[warning?.kind]
    return build ? build(warning.value) : null
}
