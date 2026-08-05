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
import { vulnerableLibraries } from '../audit/apps/classifyFindings'
import { explainWarning, hasRiskWarnings } from '../audit/apps/explainFindings'
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
            (result.files || []).some(
                (f) => f.error || f.skipped || (f.warnings || []).length > 0
            )
    )

// One line per vulnerable library: what it is, what is wrong, and the CVE to
// look up. The fixed-in version is the actionable part — it tells whoever
// maintains the app exactly what to upgrade to.
const LibraryFindings = ({ files }) => {
    const libraries = vulnerableLibraries(files)
    if (libraries.length === 0) {
        return null
    }
    return (
        <div>
            {libraries.map((library) => (
                <div key={`${library.component}@${library.version}`}>
                    <div className={classes.warningRow}>
                        <span className={classes.warningKind}>
                            {library.component} {library.version}
                        </span>
                    </div>
                    {library.vulnerabilities.map((vuln, idx) => (
                        <div key={idx} className={classes.warningRow}>
                            {describeVulnerability(vuln)}
                        </div>
                    ))}
                </div>
            ))}
        </div>
    )
}

// Where in the file a finding sits. Rendered next to the finding value in
// both the in-app details and the exported report.
const lineSuffix = (line) => (line ? i18n.t(', line {{line}}', { line }) : '')

const describeVulnerability = (vuln) => {
    const ids = vuln.identifiers?.CVE?.join(', ') || vuln.identifiers?.githubID
    const summary = vuln.identifiers?.summary
    const parts = [
        vuln.severity ? `[${vuln.severity}]` : null,
        ids,
        summary,
        vuln.below ? i18n.t('fixed in {{version}}', { version: vuln.below }) : null,
    ].filter(Boolean)
    return parts.join(' — ')
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
                            <LibraryFindings files={result.files} />
                            <FileSection
                                heading={i18n.t('Code analysis')}
                                files={partitionFiles(result.files).risky}
                            />
                            <FileSection
                                heading={i18n.t(
                                    'No risk found — reported for information'
                                )}
                                files={partitionFiles(result.files).informational}
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
const FileFindings = ({ file }) => {
    if (file.error) {
        return (
            <div className={classes.warningRow}>
                <span className={classes.fileSrc}>{file.src}</span>:{' '}
                {i18n.t('Error: {{message}}', { message: file.error })}
            </div>
        )
    }
    if (file.skipped) {
        return (
            <div className={classes.warningRow}>
                <span className={classes.fileSrc}>{file.src}</span>:{' '}
                {i18n.t('Skipped ({{reason}})', { reason: file.skipped })}
            </div>
        )
    }
    if (!file.warnings || file.warnings.length === 0) {
        return null
    }
    return (
        <div>
            <div className={classes.warningRow}>
                <span className={classes.fileSrc}>{file.src}</span>
            </div>
            {groupWarnings(file.warnings).map((group) => (
                <WarningRow key={group.key} group={group} />
            ))}
        </div>
    )
}

// A titled group of file findings. Renders nothing when the group is empty,
// so an app with only informational findings does not get an empty "Code
// analysis" heading above it.
const FileSection = ({ heading, files }) =>
    files.length === 0 ? null : (
        <div>
            <div className={classes.sectionHeading}>{heading}</div>
            {files.map((file) => (
                <FileFindings key={file.src} file={file} />
            ))}
        </div>
    )

// The same finding usually fires many times in one file — ExtJS trips the
// eval check five times over. Repeating an identical row (and an identical
// explanation) five times buries the point rather than making it, so
// identical findings collapse into one row with a count.
const groupWarnings = (warnings) => {
    const groups = new Map()
    for (const warning of warnings || []) {
        const key = `${warning.kind}:${warning.value ?? ''}`
        const existing = groups.get(key)
        if (existing) {
            existing.count += 1
        } else {
            groups.set(key, { key, warning, count: 1 })
        }
    }
    return [...groups.values()]
}

const WarningRow = ({ group }) => {
    const { warning, count } = group
    const explained = explainWarning(warning)
    return (
        <div className={classes.warningRow}>
            <span className={classes.warningKind}>
                {explained ? explained.title : warning.kind}
            </span>
            {count > 1 ? <span> {i18n.t('({{count}}x)', { count })}</span> : null}
            {/* The raw value is only shown when we have nothing better to say
                about the finding — otherwise the explanation carries it, and
                a bare "(1.4173309575166464)" is noise. */}
            {!explained && warning.value ? (
                <span> ({warning.value})</span>
            ) : null}
            {explained ? (
                <div className={classes.warningDetail}>{explained.detail}</div>
            ) : null}
        </div>
    )
}

// Split an app's files into the ones carrying a risk finding and the ones
// that only produced build-artefact observations, so the two can be shown
// under headings that say which is which.
const partitionFiles = (files) => {
    const risky = []
    const informational = []
    for (const file of files || []) {
        if (file.error || file.skipped) {
            informational.push(file)
        } else if (hasRiskWarnings(file.warnings)) {
            risky.push(file)
        } else if ((file.warnings || []).length > 0) {
            informational.push(file)
        }
    }
    return { risky, informational }
}

export const AppsAudit = ({
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
                            'Scan installed DHIS2 apps for obfuscated, encoded, or otherwise suspicious JavaScript, check the libraries they bundle against known vulnerabilities, and compare their files against a recorded integrity baseline. Each app is fetched from this server and analyzed in your browser; no instance data is sent anywhere.'
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

const formatFileFindings = (file) => {
    if (file.error) {
        return `<div class="file-error">${escapeHtml(file.src)}: ${escapeHtml(
            i18n.t('Error: {{message}}', { message: file.error })
        )}</div>`
    }
    if (file.skipped) {
        return `<div class="file-skipped">${escapeHtml(file.src)}: ${escapeHtml(
            i18n.t('Skipped ({{reason}})', { reason: file.skipped })
        )}</div>`
    }
    if (!file.warnings || file.warnings.length === 0) {
        return ''
    }
    const rows = groupWarnings(file.warnings)
        .map(({ warning, count }) => {
            const explained = explainWarning(warning)
            const title = explained
                ? escapeHtml(explained.title)
                : `<code>${escapeHtml(warning.kind)}</code>`
            const times = count > 1 ? escapeHtml(` (${count}x)`) : ''
            // Same rule as the UI: the raw value only appears when there is
            // no explanation to carry it.
            const value =
                !explained && warning.value
                    ? escapeHtml(` (${warning.value})`)
                    : ''
            const line = escapeHtml(lineSuffix(warning.location?.start?.line))
            const detail = explained
                ? `<div class="finding-detail">${escapeHtml(
                      explained.detail
                  )}</div>`
                : ''
            return `<li>${title}${times}${value}${line}${detail}</li>`
        })
        .join('')
    return `<div class="file-block"><div class="file-src">${escapeHtml(
        file.src
    )}</div><ul>${rows}</ul></div>`
}

// Risk findings first under their own heading, then everything that only
// describes how the file was built, under a heading that says so. Mirrors the
// grouping in the UI.
const formatFileSections = (files) => {
    const { risky, informational } = partitionFiles(files)
    const section = (heading, group) =>
        group.length === 0
            ? ''
            : `<div class="finding-section">${escapeHtml(heading)}</div>` +
              group.map(formatFileFindings).filter(Boolean).join('')
    return (
        section(i18n.t('Code analysis'), risky) +
        section(
            i18n.t('No risk found — reported for information'),
            informational
        )
    )
}

const buildAppsReportHtml = ({
    results,
    systemInfo,
    serverHeader,
    retireInfo,
}) => {
    const reportDate = new Date().toLocaleString()
    const total = results.length
    const failures = results.filter((r) => r.status === 'fail').length
    const warnings = results.filter((r) => r.status === 'warning').length
    const errors = results.filter((r) => r.status === 'error').length
    const passed = results.filter((r) => r.status === 'pass').length
    const notScanned = results.filter((r) => r.notScanned).length
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
                    : formatFileSections(result.files))
            return `        <tr>
            <td>
                <strong>${escapeHtml(result.app.name || result.app.key)}</strong>
                <div class="app-key">${escapeHtml(result.app.key)}</div>
            </td>
            <td>${escapeHtml(result.app.version || '-')}</td>
            <td>${escapeHtml(sourceLabel(source))}</td>
            <td class="${statusClass}">${escapeHtml(status)}</td>
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
            i18n.t('Changed without a version change:')
        )}</strong> ${drifted}<br>
        <strong>${escapeHtml(
            i18n.t('Apps with vulnerable libraries:')
        )}</strong> ${withVulnerableLibs}<br>
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
