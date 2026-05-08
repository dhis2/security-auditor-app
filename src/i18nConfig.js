import i18n from '@dhis2/d2-i18n'

// Disable i18next's default HTML-escaping of interpolated values. React
// auto-escapes for in-app rendering and the HTML report exporter uses
// escapeHtml() at the boundary; i18next's extra escape produces visible
// "&#39;" artifacts when an interpolated value contains quotes (e.g. CSP
// warning lists with 'unsafe-inline').
//
// Defined as a side-effecting module so any consumer that imports an audit
// helper or the check definitions transitively picks up the configuration —
// production code via App.jsx, tests via the check imports.
//
// Mutating `options.interpolation` after init isn't honored by i18next's
// cached interpolator, so we call init() to merge the new option in.
if (typeof i18n.init === 'function') {
    i18n.init({ interpolation: { escapeValue: false } })
}
