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
import { useInstanceInfo } from '../hooks/useInstanceInfo'
import { APP_VERSION as appVersion } from '../version'
import { downloadBlob } from '../utils/download'
import { escapeHtml } from '../utils/html'
import { getServerHeader } from '../utils/instanceInfo'
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

const STATUS_LABEL = {
    pass: () => i18n.t('Pass'),
    warning: () => i18n.t('Warning'),
    fail: () => i18n.t('Fail'),
    error: () => i18n.t('Error'),
    info: () => i18n.t('Info'),
}

const StatusBadge = ({ status }) => {
    const cls = STATUS_CLASS[status] || classes.statusInfo
    const label = (STATUS_LABEL[status] || (() => i18n.t('Unknown')))()
    return <span className={`${classes.statusBadge} ${cls}`}>{label}</span>
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
            (result.files || []).some(
                (f) => f.error || f.skipped || (f.warnings || []).length > 0
            )
    )

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
                            {(result.files || []).map((file) => (
                                <FileFindings key={file.src} file={file} />
                            ))}
                        </div>
                    </TableCell>
                </TableRow>
            )}
        </>
    )
}

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
            {file.warnings.map((w, idx) => (
                <div key={idx} className={classes.warningRow}>
                    <span className={classes.warningKind}>{w.kind}</span>
                    {w.value ? (
                        <span>
                            {' '}
                            ({w.value}
                            {w.location?.start
                                ? `, line ${w.location.start.line}`
                                : ''}
                            )
                        </span>
                    ) : null}
                </div>
            ))}
        </div>
    )
}

export const AppsAudit = ({
    status,
    results,
    progress,
    currentAppKey,
    error,
    onStart,
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
                            'Scan installed DHIS2 apps for obfuscated, encoded, or otherwise suspicious JavaScript. Each app is fetched from this server and analyzed locally; nothing is uploaded externally.'
                        )}
                    </NoticeBox>
                    <Button primary onClick={onStart}>
                        {i18n.t('Start Apps Audit')}
                    </Button>
                </div>
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

const sourceLabelForReport = (source) => {
    if (source === APP_SOURCE.BUNDLED) return 'Bundled'
    if (source === APP_SOURCE.APP_HUB) return 'App Hub'
    if (source === APP_SOURCE.MANUAL) return 'Manual'
    return 'Unknown'
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
    const rows = file.warnings
        .map((w) => {
            const value = w.value ? ` (${escapeHtml(w.value)})` : ''
            const line = w.location?.start?.line
                ? `, line ${w.location.start.line}`
                : ''
            return `<li><code>${escapeHtml(w.kind)}</code>${value}${escapeHtml(
                line
            )}</li>`
        })
        .join('')
    return `<div class="file-block"><div class="file-src">${escapeHtml(
        file.src
    )}</div><ul>${rows}</ul></div>`
}

const buildAppsReportHtml = ({ results, systemInfo, serverHeader }) => {
    const reportDate = new Date().toLocaleString()
    const total = results.length
    const failures = results.filter((r) => r.status === 'fail').length
    const warnings = results.filter((r) => r.status === 'warning').length
    const errors = results.filter((r) => r.status === 'error').length
    const passed = results.filter((r) => r.status === 'pass').length
    const notScanned = results.filter((r) => r.notScanned).length

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
            const status = (result.status || 'pass').toUpperCase()
            const statusClass = `status-${(result.status || 'pass').toLowerCase()}`
            const detailsHtml = result.error
                ? `<div class="file-error">${escapeHtml(
                      i18n.t('Error: {{message}}', { message: result.error })
                  )}</div>`
                : result.note
                ? `<div class="file-skipped">${escapeHtml(result.note)}</div>`
                : (result.files || [])
                      .map((f) => formatFileFindings(f))
                      .filter(Boolean)
                      .join('')
            return `        <tr>
            <td>
                <strong>${escapeHtml(result.app.name || result.app.key)}</strong>
                <div class="app-key">${escapeHtml(result.app.key)}</div>
            </td>
            <td>${escapeHtml(result.app.version || '-')}</td>
            <td>${escapeHtml(sourceLabelForReport(source))}</td>
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
        <strong>${escapeHtml(i18n.t('Not scanned:'))}</strong> ${notScanned}
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
