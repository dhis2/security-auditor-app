import { useState } from 'react'
import {
    Button,
    Card,
    NoticeBox,
    Table,
    TableHead,
    TableRowHead,
    TableCellHead,
    TableBody,
    TableRow,
    TableCell,
} from '@dhis2/ui'
import i18n from '@dhis2/d2-i18n'
import { APP_SOURCE, appSource } from '../audit/apps/appSource'
import { INTEGRITY, describeIntegrity } from '../audit/apps/appsBaseline'
import {
    scanIncomplete,
    vulnerableLibraries,
} from '../audit/apps/classifyFindings'
import { buildFindingSections } from '../audit/apps/groupFindings'
import { useInstanceInfo } from '../hooks/useInstanceInfo'
import { APP_VERSION as appVersion } from '../version'
import { downloadBlob } from '../utils/download'
import { escapeHtml } from '../utils/html'
import { getServerHeader } from '../utils/instanceInfo'
import { reportStatusLabel, statusLabel } from '../utils/statusLabels'
import { getReportSystemInfoItems } from '../utils/systemInfoItems'
import classes from './AppsAudit.module.css'

const sourceLabel = (source) => {
    if (source === APP_SOURCE.BUNDLED) {
        return i18n.t('Bundled')
    }
    if (source === APP_SOURCE.APP_HUB) {
        return i18n.t('App Hub')
    }
    if (source === APP_SOURCE.MANUAL) {
        return i18n.t('Manual')
    }
    return i18n.t('Unknown')
}

const STATUS_CLASS = {
    pass: classes.statusPass,
    warning: classes.statusWarning,
    fail: classes.statusFail,
    error: classes.statusError,
    info: classes.statusInfo,
}

// Shown beside the status when part of the app's code could not be examined.
//
// Separate from the status on purpose: "we could not read one chunk" is
// missing information, not a finding, and it must not be mistaken for either
// a clean result or a risk. The badge says what we found; this says how much
// of the app that answer covers.
const IncompleteMarker = ({ files }) =>
    scanIncomplete(files) ? (
        <span
            className={classes.incompleteMarker}
            title={i18n.t(
                'Some of this app’s code could not be examined — see the details. Findings below are still accurate; there may be more that was not seen.'
            )}
        >
            {'\u26A0'}
        </span>
    ) : null

const StatusBadge = ({ status }) => {
    const cls = STATUS_CLASS[status] || classes.statusInfo
    return (
        <span className={`${classes.statusBadge} ${cls}`}>
            {statusLabel(status)}
        </span>
    )
}

const ProgressBar = ({ current, total, currentAppKey }) => {
    const pct = total > 0 ? Math.round((current / total) * 100) : 0
    return (
        <div>
            <div className={classes.progressLabel}>
                {currentAppKey
                    ? i18n.t('Scanning {{current}} of {{total}}: {{key}}', {
                          current,
                          total,
                          key: currentAppKey,
                      })
                    : i18n.t('{{current}} of {{total}} apps scanned', {
                          current,
                          total,
                      })}
            </div>
            <div
                className={classes.progressTrack}
                role="progressbar"
                aria-valuenow={pct}
                aria-valuemin={0}
                aria-valuemax={100}
            >
                <div className={classes.progressBar} style={{ width: `${pct}%` }} />
            </div>
        </div>
    )
}

// Is there anything to show if the row is expanded? Deliberately not gated on
// status: most findings are now informational and leave the app at `pass`, so
// gating on status would make them unreachable in the UI.
const hasDetails = (result) =>
    Boolean(
        result.error ||
            result.note ||
            integrityNote(result) ||
            vulnerableLibraries(result.files).length > 0 ||
            (result.external?.hosts || []).length > 0 ||
            (result.files || []).some(
                (f) => f.error || f.skipped || (f.warnings || []).length > 0
            )
    )

// Findings, grouped into severity sections. Each group is headed by two
// labels — the severity and what the finding is about — so a reader can see
// how bad something is and what it concerns without reading prose.
const FindingSections = ({ files, external }) => {
    const sections = buildFindingSections(files, { external })
    if (sections.length === 0) {
        return null
    }
    return (
        <div>
            {sections.map((section) => (
                <div key={section.severity} className={classes.findingSection}>
                    {section.groups.map((group) => (
                        <div key={group.subject} className={classes.findingGroup}>
                            <div className={classes.findingHeader}>
                                <span
                                    className={`${classes.severityChip} ${
                                        classes[
                                            `severity_${section.severity}`
                                        ] || ''
                                    }`}
                                >
                                    {section.label}
                                </span>
                                <span className={classes.subjectChip}>
                                    {group.subject}
                                </span>
                            </div>
                            {group.items.map((item, idx) => (
                                <div key={idx} className={classes.findingItem}>
                                    <div className={classes.findingTitle}>
                                        {item.title}
                                    </div>
                                    {item.detail ? (
                                        <div className={classes.findingDetail}>
                                            {item.detail}
                                        </div>
                                    ) : null}
                                </div>
                            ))}
                        </div>
                    ))}
                </div>
            ))}
        </div>
    )
}

// Only worth showing when it says something an admin would act on. "Matches
// the baseline" on every row is noise.
const integrityNote = (result) =>
    result.integrity &&
    result.integrity.state !== INTEGRITY.UNCHANGED &&
    result.integrity.state !== INTEGRITY.NEW
        ? describeIntegrity(result.integrity, result.baselineEntry)
        : null

const AppRow = ({ result }) => {
    const [expanded, setExpanded] = useState(false)
    const status = result.status || 'pass'
    const expandable = hasDetails(result)

    const source = appSource(result.app)
    return (
        <>
            <TableRow>
                <TableCell>
                    <div>
                        <strong>{result.app.name || result.app.key}</strong>
                    </div>
                    <div className={classes.appKey}>{result.app.key}</div>
                </TableCell>
                <TableCell>{result.app.version || '-'}</TableCell>
                <TableCell>{sourceLabel(source)}</TableCell>
                <TableCell>
                    <StatusBadge status={status} />
                    <IncompleteMarker files={result.files} />
                </TableCell>
                <TableCell>
                    {expandable ? (
                        <Button
                            small
                            secondary
                            onClick={() => setExpanded((v) => !v)}
                        >
                            {expanded ? i18n.t('Hide') : i18n.t('Details')}
                        </Button>
                    ) : null}
                </TableCell>
            </TableRow>
            {expanded && (
                <TableRow>
                    <TableCell colSpan="5">
                        <div className={classes.details}>
                            {result.error && (
                                <div className={classes.warningRow}>
                                    {i18n.t('Error: {{message}}', {
                                        message: result.error,
                                    })}
                                </div>
                            )}
                            {result.note && (
                                <div className={classes.warningRow}>
                                    {result.note}
                                </div>
                            )}
                            {integrityNote(result) && (
                                <div className={classes.warningRow}>
                                    {integrityNote(result)}
                                </div>
                            )}
                            <FindingSections
                                files={result.files}
                                external={result.external}
                            />
                        </div>
                    </TableCell>
                </TableRow>
            )}
        </>
    )
}

// A file's code-analysis findings, explained.
//
// Each one says what triggered it and whether it matters, because the kind
// alone ("unsafe-stmt (Function)") tells a reader nothing they can act on.
// Findings that describe how the file was built rather than what is in it sit
// under a heading that states plainly that no risk was found.
export const AppsAudit = ({
    codeAnalysisEnabled,
    status,
    results,
    progress,
    currentAppKey,
    error,
    onStart,
    retireInfo,
    signatures,
    signatureError,
    baseline,
    baselineError,
    savingBaseline,
    onAcceptBaseline,
}) => {
    const [generating, setGenerating] = useState(false)
    const [exportError, setExportError] = useState(null)
    const { systemInfo: sharedSystemInfo } = useInstanceInfo()

    const generateHtmlReport = async () => {
        setGenerating(true)
        setExportError(null)
        try {
            const systemInfo = sharedSystemInfo || {}
            const fetchedHeader = await getServerHeader(systemInfo.contextPath)
            const serverHeader =
                fetchedHeader === null
                    ? i18n.t('Unable to detect')
                    : fetchedHeader || i18n.t('Not disclosed')
            const html = buildAppsReportHtml({
                results,
                systemInfo,
                serverHeader,
                retireInfo,
                codeAnalysisEnabled,
            })
            const blob = new Blob([html], { type: 'text/html' })
            downloadBlob(
                blob,
                `dhis2-apps-audit-${new Date().toISOString().split('T')[0]}.html`
            )
        } catch (err) {
            setExportError(err.message || i18n.t('Unknown error'))
        } finally {
            setGenerating(false)
        }
    }

    if (status === 'idle') {
        return (
            <div className={classes.container}>
                <div className={classes.panelWithAction}>
                    <NoticeBox title={i18n.t('Apps Audit')}>
                        {i18n.t(
                            'Check the libraries each installed app bundles against known vulnerabilities, and compare its files against a recorded integrity baseline to detect code that changed without a version change. Each app is fetched from this server and examined in your browser; no instance data is sent anywhere. Obfuscation and code analysis is an extra, slower pass that is off by default — enable it in Configuration.'
                        )}
                    </NoticeBox>
                    <Button primary onClick={onStart}>
                        {i18n.t('Start Apps Audit')}
                    </Button>
                </div>
                <RetirePanel
                    retireInfo={retireInfo}
                    vulnerable={0}
                    signatures={signatures}
                    signatureError={signatureError}
                />
            </div>
        )
    }

    if (status === 'running') {
        return (
            <div className={classes.container}>
                <Card className={classes.card}>
                    <ProgressBar
                        current={progress.current}
                        total={progress.total}
                        currentAppKey={currentAppKey}
                    />
                </Card>
                {results.length > 0 && <ResultsTable results={results} />}
            </div>
        )
    }

    if (status === 'error' && results.length === 0) {
        return (
            <div className={classes.container}>
                <div className={classes.panelWithAction}>
                    <NoticeBox error title={i18n.t('Apps Audit failed')}>
                        {error ||
                            i18n.t(
                                'Could not list installed apps. The user may lack permission to read /api/apps.'
                            )}
                    </NoticeBox>
                    <Button onClick={onStart}>
                        {i18n.t('Re-run Apps Audit')}
                    </Button>
                </div>
            </div>
        )
    }

    // completed
    const failures = results.filter((r) => r.status === 'fail').length
    const warnings = results.filter((r) => r.status === 'warning').length
    const notScanned = results.filter((r) => r.notScanned).length
    const partiallyExamined = results.filter((r) => scanIncomplete(r.files)).length
    const drifted = results.filter(
        (r) => r.integrity?.state === INTEGRITY.DRIFT
    ).length
    const vulnerableAppCount = results.filter(
        (r) => vulnerableLibraries(r.files).length > 0
    ).length
    const hashed = results.filter(
        (r) => r.integrity && r.integrity.state !== INTEGRITY.UNKNOWN
    ).length
    return (
        <div className={classes.container}>
            <div className={classes.panelWithAction}>
                <NoticeBox
                    title={i18n.t('Apps Audit completed')}
                    error={failures > 0}
                    warning={warnings > 0 && failures === 0}
                    success={failures === 0 && warnings === 0}
                >
                    {failures > 0
                        ? i18n.t(
                              'Found {{failures}} app(s) with failing findings. Review the details below.',
                              { failures }
                          )
                        : warnings > 0
                        ? i18n.t(
                              'Apps Audit completed with {{warnings}} warning(s). Review recommended.',
                              { warnings }
                          )
                        : i18n.t('All scanned apps look clean.')}
                    {notScanned > 0 &&
                        ' ' +
                            i18n.t(
                                '{{notScanned}} app(s) could not be scanned — see details.',
                                { notScanned }
                            )}
                </NoticeBox>
                <Button onClick={onStart}>
                    {i18n.t('Re-run Apps Audit')}
                </Button>
            </div>
            <RetirePanel
                retireInfo={retireInfo}
                vulnerable={vulnerableAppCount}
                signatures={signatures}
                signatureError={signatureError}
            />
            <BaselinePanel
                baseline={baseline}
                baselineError={baselineError}
                saving={savingBaseline}
                onAccept={onAcceptBaseline}
                drifted={drifted}
                hashed={hashed}
                total={results.length}
            />
            <ResultsTable results={results} />
            <div className={classes.reportButton}>
                {exportError && (
                    <NoticeBox error title={i18n.t('Failed to generate report')}>
                        {exportError}
                    </NoticeBox>
                )}
                <Button onClick={generateHtmlReport} disabled={generating}>
                    {generating ? i18n.t('Generating...') : i18n.t('Save Report')}
                </Button>
            </div>
        </div>
    )
}

// Known-vulnerable library detection, and how much to trust a clean result.
//
// The signature set is vendored at build time so the scan works offline, so
// "no known vulnerabilities" only means "none as of this date". Showing the
// date turns a silent assumption into something the reader can weigh.
// How the signatures reached us, so a reader can weigh a clean result.
const originLabel = (retireInfo, signatures) => {
    const date = formatSignatureDate(
        retireInfo?.retrievedAt || signatures?.retrievedAt
    )
    if (!date) {
        return null
    }
    return (retireInfo?.origin || (signatures ? 'downloaded' : 'bundled')) ===
        'downloaded'
        ? i18n.t('Signatures downloaded {{date}}.', { date })
        : i18n.t('Using the signatures bundled with this app ({{date}}).', {
              date,
          })
}

const formatSignatureDate = (value) => {
    if (!value) {
        return null
    }
    const parsed = new Date(value)
    return Number.isNaN(parsed.getTime())
        ? String(value)
        : parsed.toLocaleString()
}

const RetirePanel = ({ retireInfo, vulnerable, signatures, signatureError }) => {
    const origin = originLabel(retireInfo, signatures)
    const unavailable = retireInfo?.unavailable
    return (
        <NoticeBox
            title={i18n.t('Vulnerable library check')}
            error={!unavailable && vulnerable > 0}
            warning={Boolean(unavailable || signatureError)}
            success={!unavailable && !signatureError && vulnerable === 0}
        >
            {unavailable
                ? i18n.t(
                      'The Retire.js signature data could not be loaded, so apps were not checked for known-vulnerable libraries.'
                  )
                : vulnerable > 0
                ? i18n.t(
                      '{{vulnerable}} app(s) bundle a library with a known vulnerability.',
                      { vulnerable }
                  )
                : retireInfo
                ? i18n.t('No known-vulnerable libraries found.')
                : i18n.t(
                      'Apps are checked against the Retire.js advisory database. Starting a scan downloads current signatures if the stored set has aged out; if that download fails, the scan continues with the newest set available.'
                  )}
            {origin ? ` ${origin}` : ''}
            {signatureError
                ? ' ' +
                  i18n.t('Last download attempt failed: {{message}}', {
                      message: signatureError,
                  })
                : ''}
            {' '}
            {i18n.t(
                'Signatures can be fetched on demand from the Configuration tab.'
            )}
        </NoticeBox>
    )
}

// Baseline state and the one action that changes it.
//
// Accepting is explicit and deliberately worded as trust, not bookkeeping: it
// records whatever is on the server right now as the reference for every
// future run. Doing that while drift is unexplained would bless it silently,
// so that case is called out before the button.
const BaselinePanel = ({
    baseline,
    baselineError,
    saving,
    onAccept,
    drifted,
    hashed,
    total,
}) => {
    const recorded = baseline?.recordedAt
        ? new Date(baseline.recordedAt).toLocaleString()
        : null
    const noHashes = hashed === 0 && total > 0

    return (
        <div className={classes.panelWithAction}>
            <NoticeBox
                title={i18n.t('Integrity baseline')}
                error={drifted > 0}
                warning={noHashes}
                success={Boolean(recorded) && drifted === 0 && !noHashes}
            >
                {baselineError ? (
                    baselineError
                ) : noHashes ? (
                    i18n.t(
                        'No app files could be hashed, so integrity was not checked. Web Crypto is only available over HTTPS.'
                    )
                ) : drifted > 0 ? (
                    i18n.t(
                        '{{drifted}} app(s) changed on disk without a version change. Investigate before accepting a new baseline — accepting records the current code as trusted.',
                        { drifted }
                    )
                ) : recorded ? (
                    i18n.t(
                        'Compared against the baseline recorded {{recorded}}. No app changed without a version change.',
                        { recorded }
                    )
                ) : (
                    i18n.t(
                        'No baseline recorded yet. Accept the current state to start detecting apps whose code changes without a version change.'
                    )
                )}
            </NoticeBox>
            <Button
                onClick={onAccept}
                disabled={saving || noHashes}
                destructive={drifted > 0}
            >
                {saving
                    ? i18n.t('Saving...')
                    : recorded
                    ? i18n.t('Accept current state as baseline')
                    : i18n.t('Record baseline')}
            </Button>
        </div>
    )
}

// The report renders the same severity sections as the UI, from the same
// model — so the two cannot describe an app differently.
const formatFindingSections = (files, external) =>
    buildFindingSections(files, { external })
        .map(
            (section) => `<div class="finding-section">${section.groups
                .map(
                    (group) => `<div class="finding-group">
                <div class="finding-header"><span class="chip chip-${escapeHtml(
                    section.severity
                )}">${escapeHtml(section.label)}</span><span class="chip chip-subject">${escapeHtml(
                        group.subject
                    )}</span></div>
                <ul>${group.items
                    .map(
                        (item) =>
                            `<li><span class="finding-title">${escapeHtml(
                                item.title
                            )}</span>${
                                item.detail
                                    ? `<div class="finding-detail">${escapeHtml(
                                          item.detail
                                      )}</div>`
                                    : ''
                            }</li>`
                    )
                    .join('')}</ul>
            </div>`
                )
                .join('')}</div>`
        )
        .join('')

const buildAppsReportHtml = ({
    results,
    systemInfo,
    serverHeader,
    retireInfo,
    codeAnalysisEnabled,
}) => {
    const reportDate = new Date().toLocaleString()
    const total = results.length
    const failures = results.filter((r) => r.status === 'fail').length
    const warnings = results.filter((r) => r.status === 'warning').length
    const errors = results.filter((r) => r.status === 'error').length
    const passed = results.filter((r) => r.status === 'pass').length
    const notScanned = results.filter((r) => r.notScanned).length
    const partiallyExamined = results.filter((r) => scanIncomplete(r.files)).length
    const drifted = results.filter(
        (r) => r.integrity?.state === INTEGRITY.DRIFT
    ).length
    const withVulnerableLibs = results.filter(
        (r) => vulnerableLibraries(r.files).length > 0
    ).length

    const order = { fail: 0, error: 1, warning: 2, info: 3, pass: 4 }
    const sorted = [...results].sort(
        (a, b) => (order[a.status] ?? 99) - (order[b.status] ?? 99)
    )

    const systemInfoHtml = getReportSystemInfoItems(systemInfo, {
        webServer: serverHeader,
        appVersion,
    })
        .map(
            (item) => `        <div class="info-item">
            <div class="info-label">${escapeHtml(item.label)}</div>
            <div class="info-value">${escapeHtml(item.value || i18n.t('N/A'))}</div>
        </div>`
        )
        .join('\n')

    const rows = sorted
        .map((result) => {
            const source = appSource(result.app)
            const status = reportStatusLabel(result.status || 'pass')
            const statusClass = `status-${(result.status || 'pass').toLowerCase()}`
            const librariesHtml = vulnerableLibraries(result.files)
                .map((library) => {
                    const rows = library.vulnerabilities
                        .map(
                            (v) =>
                                `<li>${escapeHtml(describeVulnerability(v))}</li>`
                        )
                        .join('')
                    return `<div class="file-block"><div class="file-src">${escapeHtml(
                        `${library.component} ${library.version}`
                    )}</div><ul>${rows}</ul></div>`
                })
                .join('')
            const note = integrityNote(result)
            const integrityHtml = note
                ? `<div class="${
                      result.integrity?.state === INTEGRITY.DRIFT
                          ? 'file-error'
                          : 'file-skipped'
                  }">${escapeHtml(note)}</div>`
                : ''
            const detailsHtml =
                integrityHtml +
                librariesHtml +
                (result.error
                    ? `<div class="file-error">${escapeHtml(
                          i18n.t('Error: {{message}}', { message: result.error })
                      )}</div>`
                    : result.note
                    ? `<div class="file-skipped">${escapeHtml(result.note)}</div>`
                    : formatFindingSections(result.files, result.external))
            return `        <tr>
            <td>
                <strong>${escapeHtml(result.app.name || result.app.key)}</strong>
                <div class="app-key">${escapeHtml(result.app.key)}</div>
            </td>
            <td>${escapeHtml(result.app.version || '-')}</td>
            <td>${escapeHtml(sourceLabel(source))}</td>
            <td class="${statusClass}">${escapeHtml(status)}${
                scanIncomplete(result.files)
                    ? ` <span class="incomplete" title="${escapeHtml(
                          i18n.t(
                              'Some of this app’s code could not be examined — see Not examined below.'
                          )
                      )}">\u26A0</span>`
                    : ''
            }</td>
            <td>${detailsHtml}</td>
        </tr>`
        })
        .join('\n')

    return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>${escapeHtml(i18n.t('DHIS2 Apps Audit Report'))}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; color: #333; }
        h1 { color: #2c5aa0; border-bottom: 3px solid #2c5aa0; padding-bottom: 10px; }
        h2 { color: #2c5aa0; margin-top: 30px; border-bottom: 2px solid #e0e0e0; padding-bottom: 5px; }
        .header-info { background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background-color: #2c5aa0; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #e0e0e0; vertical-align: top; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .status-pass { color: #2e7d32; font-weight: bold; }
        .status-warning { color: #e65100; font-weight: bold; }
        .status-fail { color: #c62828; font-weight: bold; }
        .status-error { color: #6a1b9a; font-weight: bold; }
        .status-info { color: #1565c0; font-weight: bold; }
        .app-key { font-family: monospace; font-size: 0.85em; color: #757575; margin-top: 4px; }
        .file-block { margin-bottom: 8px; }
        .file-src { font-family: monospace; font-size: 0.9em; color: #424242; }
        .file-error { font-size: 0.9em; color: #c62828; }
        .file-skipped { font-size: 0.9em; color: #757575; font-style: italic; }
        .finding-section { font-size: 0.8em; font-weight: bold; text-transform: uppercase; letter-spacing: 0.04em; color: #6e7a8a; margin: 14px 0 6px; padding-top: 8px; border-top: 1px solid #e8edf2; }
        .incomplete { color: #b26a00; cursor: help; }
        .finding-section { margin-top: 10px; }
        .finding-group { margin-bottom: 10px; }
        .finding-header { margin-bottom: 4px; }
        .chip { display: inline-block; font-size: 0.75em; font-weight: bold; letter-spacing: 0.04em; padding: 2px 7px; border-radius: 10px; margin-right: 6px; }
        .chip-critical { background: #7f0000; color: #fff; }
        .chip-high { background: #c62828; color: #fff; }
        .chip-medium { background: #e65100; color: #fff; }
        .chip-low { background: #f9a825; color: #3b2f00; }
        .chip-info { background: #e0e6ec; color: #4a5561; }
        .chip-unexamined { background: #6e7a8a; color: #fff; }
        .chip-subject { background: #f2f5f8; color: #2c3e50; font-family: monospace; font-weight: normal; letter-spacing: 0; }
        .finding-title { color: #34404d; }
        .finding-detail { font-size: 0.9em; color: #6e7a8a; margin-top: 2px; max-width: 70ch; }
        ul { margin: 4px 0 8px 18px; padding: 0; }
        li { font-size: 0.9em; color: #4a4a4a; }
        code { font-family: monospace; }
        .system-info { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-top: 15px; }
        .info-item { padding: 10px; background-color: #f9f9f9; border-left: 3px solid #2c5aa0; }
        .info-label { font-weight: bold; color: #666; font-size: 0.85em; text-transform: uppercase; }
        .info-value { margin-top: 3px; color: #333; }
    </style>
</head>
<body>
    <h1>${escapeHtml(i18n.t('DHIS2 Apps Audit Report'))}</h1>
    <div class="header-info">
        <strong>${escapeHtml(i18n.t('Report Generated:'))}</strong> ${escapeHtml(reportDate)}<br>
        <strong>${escapeHtml(i18n.t('Total Apps:'))}</strong> ${total}<br>
        <strong>${escapeHtml(i18n.t('Failed:'))}</strong> ${failures}<br>
        <strong>${escapeHtml(i18n.t('Warnings:'))}</strong> ${warnings}<br>
        <strong>${escapeHtml(i18n.t('Errors:'))}</strong> ${errors}<br>
        <strong>${escapeHtml(i18n.t('Passed:'))}</strong> ${passed}<br>
        <strong>${escapeHtml(i18n.t('Not scanned:'))}</strong> ${notScanned}<br>
        <strong>${escapeHtml(
            i18n.t('Partially examined:')
        )}</strong> ${partiallyExamined}<br>
        <strong>${escapeHtml(
            i18n.t('Changed without a version change:')
        )}</strong> ${drifted}<br>
        <strong>${escapeHtml(
            i18n.t('Apps with vulnerable libraries:')
        )}</strong> ${withVulnerableLibs}<br>
        <strong>${escapeHtml(
            i18n.t('Obfuscation and code analysis:')
        )}</strong> ${escapeHtml(
        codeAnalysisEnabled ? i18n.t('enabled') : i18n.t('not run')
    )}<br>
        <strong>${escapeHtml(
            i18n.t('Retire.js signatures:')
        )}</strong> ${escapeHtml(
        retireInfo?.retrievedAt || i18n.t('not loaded')
    )}
    </div>

    <h2>${escapeHtml(i18n.t('System Information'))}</h2>
    <div class="system-info">
${systemInfoHtml}
    </div>

    <h2>${escapeHtml(i18n.t('App Findings'))}</h2>
    <table>
        <thead>
            <tr>
                <th>${escapeHtml(i18n.t('App'))}</th>
                <th>${escapeHtml(i18n.t('Version'))}</th>
                <th>${escapeHtml(i18n.t('Source'))}</th>
                <th>${escapeHtml(i18n.t('Status'))}</th>
                <th>${escapeHtml(i18n.t('Findings'))}</th>
            </tr>
        </thead>
        <tbody>
${rows}
        </tbody>
    </table>
</body>
</html>
`
}

const ResultsTable = ({ results }) => {
    // Sort: fail > error > warning > info > pass
    const order = { fail: 0, error: 1, warning: 2, info: 3, pass: 4 }
    const sorted = [...results].sort(
        (a, b) => (order[a.status] ?? 99) - (order[b.status] ?? 99)
    )
    return (
        <Card className={classes.card}>
            <Table>
                <TableHead>
                    <TableRowHead>
                        <TableCellHead>{i18n.t('App')}</TableCellHead>
                        <TableCellHead>{i18n.t('Version')}</TableCellHead>
                        <TableCellHead>{i18n.t('Source')}</TableCellHead>
                        <TableCellHead>{i18n.t('Status')}</TableCellHead>
                        <TableCellHead>{''}</TableCellHead>
                    </TableRowHead>
                </TableHead>
                <TableBody>
                    {sorted.map((result) => (
                        <AppRow key={result.app.key} result={result} />
                    ))}
                </TableBody>
            </Table>
        </Card>
    )
}
