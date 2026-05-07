// Minimal HTML escaper for the small set of metacharacters that matter when
// interpolating user-influenced text into a static HTML template. Used by the
// audit-report exporter so data like usernames, server-header values, or
// system-info strings cannot inject markup into the report.
const ESCAPE_MAP = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
}

export const escapeHtml = (value) => {
    if (value === null || value === undefined) {
        return ''
    }
    return String(value).replace(/[&<>"']/g, (ch) => ESCAPE_MAP[ch])
}
