import { useCallback, useEffect, useRef, useState } from 'react'
import {
    Card,
    Button,
    InputField,
    NoticeBox,
    ButtonStrip,
    CircularLoader,
} from '@dhis2/ui'
import i18n from '@dhis2/d2-i18n'
import { SCAN_LIMIT_BOUNDS } from '../audit/apps/scanLimits'
import { DEFAULT_CONFIG, useAuditConfig } from '../hooks/useAuditConfig'
import {
    REQUIRED_CONFIG_KEYS,
    validateConfig,
} from '../utils/configValidation'
import { downloadBlob } from '../utils/download'
import classes from './ConfigurationPanel.module.css'

export const ConfigurationPanel = () => {
    const { config, loading, error, resetConfig, saveConfig } = useAuditConfig()

    const [localConfig, setLocalConfig] = useState(config)
    const [saving, setSaving] = useState(false)
    const [saveMessage, setSaveMessage] = useState(null)
    const fileInputRef = useRef(null)
    const messageTimerRef = useRef(null)

    // Update local config when global config changes
    useEffect(() => {
        setLocalConfig(config)
    }, [config])

    // Show a transient feedback message; auto-clears after `timeoutMs`. Cancels
    // any pending clear-timer so successive calls don't blank out a newer
    // message early. The cleanup effect below clears the timer on unmount so
    // we don't `setState` on an unmounted component.
    const flashMessage = useCallback((message, timeoutMs = 3000) => {
        if (messageTimerRef.current) {
            clearTimeout(messageTimerRef.current)
        }
        setSaveMessage(message)
        messageTimerRef.current = setTimeout(() => {
            setSaveMessage(null)
            messageTimerRef.current = null
        }, timeoutMs)
    }, [])

    useEffect(
        () => () => {
            if (messageTimerRef.current) {
                clearTimeout(messageTimerRef.current)
            }
        },
        []
    )

    const handleChange = (key, value) => {
        setLocalConfig((prev) => ({ ...prev, [key]: parseInt(value, 10) }))
        setSaveMessage(null)
    }

    const handleSave = async () => {
        const errors = validateConfig(localConfig)
        if (errors.length > 0) {
            flashMessage({ type: 'error', text: errors.join('. ') }, 5000)
            return
        }

        setSaving(true)
        const result = await saveConfig(localConfig)
        flashMessage(
            result.success
                ? { type: 'success', text: i18n.t('Configuration saved successfully') }
                : { type: 'error', text: i18n.t('Failed to save configuration') }
        )
        setSaving(false)
    }

    const handleReset = async () => {
        setSaving(true)
        const result = await resetConfig()
        flashMessage(
            result.success
                ? { type: 'success', text: i18n.t('Configuration reset to defaults') }
                : { type: 'error', text: i18n.t('Failed to reset configuration') }
        )
        setSaving(false)
    }

    const handleExport = () => {
        try {
            const blob = new Blob([JSON.stringify(config, null, 2)], {
                type: 'application/json',
            })
            downloadBlob(
                blob,
                `security-auditor-config-${new Date().toISOString().split('T')[0]}.json`
            )
            flashMessage({ type: 'success', text: i18n.t('Configuration exported successfully') })
        } catch (err) {
            flashMessage({ type: 'error', text: i18n.t('Failed to export configuration') })
        }
    }

    const handleImport = async (event) => {
        const file = event.target.files?.[0]
        if (!file) return

        setSaving(true)

        try {
            const text = await file.text()
            const importedConfig = JSON.parse(text)

            if (!importedConfig || typeof importedConfig !== 'object') {
                throw new Error(
                    i18n.t('Imported file is not a valid configuration object')
                )
            }

            // Sanity check: the file should contain at least one recognized key.
            // Rejects unrelated JSON without rejecting older exports that simply
            // pre-date a more recent config field (those are upgraded via the
            // DEFAULT_CONFIG merge below).
            const hasAnyKnownKey = REQUIRED_CONFIG_KEYS.some(
                (key) => key in importedConfig
            )
            if (!hasAnyKnownKey) {
                throw new Error(
                    i18n.t('No recognized configuration fields found')
                )
            }

            // Merge with defaults so missing keys (e.g. from an older export)
            // get filled in automatically.
            const mergedConfig = { ...DEFAULT_CONFIG, ...importedConfig }

            const errors = validateConfig(mergedConfig)
            if (errors.length > 0) {
                throw new Error(errors.join('. '))
            }

            const result = await saveConfig(mergedConfig)

            if (result.success) {
                setLocalConfig(mergedConfig)
                flashMessage({ type: 'success', text: i18n.t('Configuration imported successfully') })
            } else {
                flashMessage({ type: 'error', text: i18n.t('Failed to save imported configuration') })
            }
        } catch (err) {
            flashMessage({
                type: 'error',
                text: `${i18n.t('Failed to import configuration')}: ${err.message}`,
            })
        } finally {
            setSaving(false)
            if (fileInputRef.current) {
                fileInputRef.current.value = ''
            }
        }
    }

    const handleImportClick = () => {
        fileInputRef.current?.click()
    }

    if (loading) {
        return (
            <div className={classes.container}>
                <Card className={classes.card}>
                    <CircularLoader />
                </Card>
            </div>
        )
    }

    return (
        <div className={classes.container}>
        <Card className={classes.card}>
            <div className={classes.header}>
                <h3 className={classes.title}>{i18n.t('Security Audit Configuration')}</h3>
                <p className={classes.subtitle}>
                    {i18n.t('Configure thresholds and parameters for security checks')}
                </p>
            </div>

            {error && (
                <NoticeBox error title={i18n.t('Error')}>
                    {error}
                </NoticeBox>
            )}

            {saveMessage && (
                <NoticeBox
                    title={saveMessage.type === 'success' ? i18n.t('Success') : i18n.t('Error')}
                    success={saveMessage.type === 'success'}
                    error={saveMessage.type === 'error'}
                >
                    {saveMessage.text}
                </NoticeBox>
            )}

            <div className={classes.configGrid}>
                <InputField
                    label={i18n.t('Minimum Password Length')}
                    type="number"
                    min="1"
                    max="50"
                    value={String(localConfig.minPasswordLength)}
                    onChange={({ value }) => handleChange('minPasswordLength', value)}
                    helpText={i18n.t('Minimum number of characters required for passwords')}
                />

                <InputField
                    label={i18n.t('Maximum Inactive Months')}
                    type="number"
                    min="1"
                    max="24"
                    value={String(localConfig.maxInactiveMonths)}
                    onChange={({ value }) => handleChange('maxInactiveMonths', value)}
                    helpText={i18n.t('Flag accounts inactive for more than this many months')}
                />

                <InputField
                    label={i18n.t('Maximum Password Age (Days)')}
                    type="number"
                    min="30"
                    max="1095"
                    value={String(localConfig.maxPasswordAgeDays)}
                    onChange={({ value }) => handleChange('maxPasswordAgeDays', value)}
                    helpText={i18n.t('Flag passwords older than this many days')}
                />

                <InputField
                    label={i18n.t('Maximum Privileged Users')}
                    type="number"
                    min="1"
                    max="50"
                    value={String(localConfig.maxSuperUserRoles)}
                    onChange={({ value }) => handleChange('maxSuperUserRoles', value)}
                    helpText={i18n.t(
                        'Threshold for the number of users holding privileged authorities (ALL, F_PUBLIC_ROUTE_ADD, F_IMPERSONATE_USER, or F_SYSTEM_SETTING) before a warning is raised'
                    )}
                />

                <InputField
                    label={i18n.t('Maximum Audit Pages Per Query')}
                    type="number"
                    min="100"
                    max="50000"
                    value={String(localConfig.maxAuditPages)}
                    onChange={({ value }) => handleChange('maxAuditPages', value)}
                    helpText={i18n.t(
                        'Hard cap on how many pages a single audit query will fetch. With the default page size of 200, 5000 pages allows up to 1,000,000 matched rows. Raise for very large instances; lower as a defensive limit.'
                    )}
                />

                <InputField
                    label={i18n.t('Apps Audit Concurrency')}
                    type="number"
                    min="1"
                    max="16"
                    value={String(localConfig.maxAppAuditConcurrency)}
                    onChange={({ value }) =>
                        handleChange('maxAppAuditConcurrency', value)
                    }
                    helpText={i18n.t(
                        'Number of installed apps scanned in parallel by the Apps Audit. Higher values fetch faster but use more CPU during obfuscation analysis.'
                    )}
                />

                <InputField
                    label={i18n.t('Maximum Files Scanned Per App')}
                    type="number"
                    min={String(SCAN_LIMIT_BOUNDS.maxAppFilesScanned.min)}
                    max={String(SCAN_LIMIT_BOUNDS.maxAppFilesScanned.max)}
                    value={String(localConfig.maxAppFilesScanned)}
                    onChange={({ value }) =>
                        handleChange('maxAppFilesScanned', value)
                    }
                    helpText={i18n.t(
                        'The Apps Audit follows an app’s module graph (entry scripts, modulepreloads and lazy-loaded chunks). This bounds how many files one app may contribute. DHIS2 2.43 apps use 2-5. Anything skipped because of this limit is listed in the findings.'
                    )}
                />

                <InputField
                    label={i18n.t('Maximum MB Scanned Per App')}
                    type="number"
                    min={String(SCAN_LIMIT_BOUNDS.maxAppScanMb.min)}
                    max={String(SCAN_LIMIT_BOUNDS.maxAppScanMb.max)}
                    value={String(localConfig.maxAppScanMb)}
                    onChange={({ value }) => handleChange('maxAppScanMb', value)}
                    helpText={i18n.t(
                        'Total JavaScript analyzed for a single app. DHIS2 2.43 apps total 1.3-7.2 MB.'
                    )}
                />

                <InputField
                    label={i18n.t('Maximum MB Per App File')}
                    type="number"
                    min={String(SCAN_LIMIT_BOUNDS.maxAppFileMb.min)}
                    max={String(SCAN_LIMIT_BOUNDS.maxAppFileMb.max)}
                    value={String(localConfig.maxAppFileMb)}
                    onChange={({ value }) => handleChange('maxAppFileMb', value)}
                    helpText={i18n.t(
                        'Largest single file the analyzer will parse. Parsing runs on this browser tab’s main thread, so a very large chunk stalls the UI. Raising this above 5 also runs into the analyzer failing outright on the largest DHIS2 bundle.'
                    )}
                />

                <InputField
                    label={i18n.t('Minimum Encoded Literal Length')}
                    type="number"
                    min={String(SCAN_LIMIT_BOUNDS.minEncodedLiteralLength.min)}
                    max={String(SCAN_LIMIT_BOUNDS.minEncodedLiteralLength.max)}
                    value={String(localConfig.minEncodedLiteralLength)}
                    onChange={({ value }) =>
                        handleChange('minEncodedLiteralLength', value)
                    }
                    helpText={i18n.t(
                        'Encoded-literal findings shorter than this are not reported. The analyzer scores short ordinary strings — i18n event names, DHIS2 error codes like "E7113" — as candidate base64. Set to 0 to report every one.'
                    )}
                />
            </div>

            <ButtonStrip className={classes.actions}>
                <Button primary onClick={handleSave} disabled={saving}>
                    {saving ? i18n.t('Saving...') : i18n.t('Save Configuration')}
                </Button>
                <Button onClick={handleReset} disabled={saving}>
                    {i18n.t('Reset to Defaults')}
                </Button>
            </ButtonStrip>

            <input
                ref={fileInputRef}
                type="file"
                accept="application/json,.json"
                onChange={handleImport}
                style={{ display: 'none' }}
            />
        </Card>

        <Card className={classes.card}>
            <div className={classes.header}>
                <h3 className={classes.title}>{i18n.t('Import and Export')}</h3>
                <p className={classes.subtitle}>
                    {i18n.t('Export configuration as JSON file or import from a saved file')}
                </p>
            </div>

            <ButtonStrip className={classes.actions}>
                <Button onClick={handleExport} disabled={saving}>
                    {i18n.t('Export Configuration')}
                </Button>
                <Button onClick={handleImportClick} disabled={saving}>
                    {i18n.t('Import Configuration')}
                </Button>
            </ButtonStrip>
        </Card>
    </div>
    )
}
