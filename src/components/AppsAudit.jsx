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
import classes from './AppsAudit.module.css'

const sourceLabel = (source) => {
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

const AppRow = ({ result }) => {
    const [expanded, setExpanded] = useState(false)
    const status = result.status || 'pass'
    const expandable =
        status !== 'pass' &&
        ((result.files && result.files.length > 0) || result.error)

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
    if (status === 'idle') {
        return (
            <div className={classes.container}>
                <Card className={classes.card}>
                    <div className={classes.cardHeaderRow}>
                        <div className={classes.cardHeaderText}>
                            <h3>{i18n.t('Apps Audit')}</h3>
                            <p>
                                {i18n.t(
                                    'Scan installed DHIS2 apps for obfuscated, encoded, or otherwise suspicious JavaScript. Each app is fetched from this server and analyzed locally; nothing is uploaded externally.'
                                )}
                            </p>
                        </div>
                        <Button primary onClick={onStart}>
                            {i18n.t('Start Apps Audit')}
                        </Button>
                    </div>
                </Card>
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
                <NoticeBox error title={i18n.t('Apps Audit failed')}>
                    {error ||
                        i18n.t(
                            'Could not list installed apps. The user may lack permission to read /api/apps.'
                        )}
                </NoticeBox>
                <Card className={classes.card}>
                    <Button onClick={onStart}>{i18n.t('Re-run Apps Audit')}</Button>
                </Card>
            </div>
        )
    }

    // completed
    const failures = results.filter((r) => r.status === 'fail').length
    const warnings = results.filter((r) => r.status === 'warning').length
    return (
        <div className={classes.container}>
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
            </NoticeBox>
            <ResultsTable results={results} />
            <Card className={classes.card}>
                <Button onClick={onStart}>{i18n.t('Re-run Apps Audit')}</Button>
            </Card>
        </div>
    )
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
