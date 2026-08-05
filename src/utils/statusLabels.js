import i18n from '@dhis2/d2-i18n'

// Status vocabulary for both audits, in one place so the two tabs and the two
// exported reports cannot drift apart.
//
// `fail` is shown as "Risk", not "Fail". "Fail" conflates two outcomes an
// operator has to tell apart: the audit found something wrong with the
// system, or the audit itself did not complete. Those need different
// responses — fix the finding, versus work out why the check could not run —
// and a column of FAILs gives no clue which you are looking at.
//
//   Risk     the check ran and found something to act on
//   Warning  the check ran and found something worth reviewing
//   Error    the check could not complete; nothing is known either way
//   Info     reported for information; no risk found
//   Pass     the check ran and found nothing
//
// The internal status keys are unchanged — `fail` is still `fail` in result
// objects and report CSS classes. Only what a person reads is renamed; the
// keys are an implementation detail with no audience.
const STATUS_LABEL = {
    pass: () => i18n.t('Pass'),
    warning: () => i18n.t('Warning'),
    fail: () => i18n.t('Risk'),
    error: () => i18n.t('Error'),
    info: () => i18n.t('Info'),
    running: () => i18n.t('Running'),
}

// Uppercase variants for the exported HTML reports, which style the status
// column as a shouted keyword.
//
// The uppercase form is translated directly rather than upper-casing the
// sentence-case label: case mapping is lossy in several locales (Turkish
// dotted/dotless i, German ß) and a translator may want a different word
// length entirely for a column heading.
const REPORT_STATUS_LABEL = {
    pass: () => i18n.t('PASS'),
    warning: () => i18n.t('WARNING'),
    fail: () => i18n.t('RISK'),
    error: () => i18n.t('ERROR'),
    info: () => i18n.t('INFO'),
    running: () => i18n.t('RUNNING'),
}

export const statusLabel = (status) =>
    (STATUS_LABEL[status] || (() => i18n.t('Unknown')))()

export const reportStatusLabel = (status) =>
    (REPORT_STATUS_LABEL[status] || (() => i18n.t('UNKNOWN')))()
