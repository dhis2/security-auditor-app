import React, { useState, useRef } from 'react'
import {
    Card,
    Button,
    InputField,
    NoticeBox,
    ButtonStrip,
    CircularLoader,
} from '@dhis2/ui'
import i18n from '@dhis2/d2-i18n'
import { useAuditConfig } from '../hooks/useAuditConfig'
import classes from './ConfigurationPanel.module.css'

export const ConfigurationPanel = () => {
    const {
        config,
        loading,
        error,
        updateConfigValue,
        resetConfig,
        saveConfig,
    } = useAuditConfig()

    const [localConfig, setLocalConfig] = useState(config)
    const [saving, setSaving] = useState(false)
    const [saveMessage, setSaveMessage] = useState(null)
    const fileInputRef = useRef(null)

    // Update local config when global config changes
    React.useEffect(() => {
        setLocalConfig(config)
    }, [config])

    const handleChange = (key, value) => {
        setLocalConfig((prev) => ({ ...prev, [key]: parseInt(value, 10) }))
        setSaveMessage(null)
    }

    const handleSave = async () => {
        setSaving(true)
        setSaveMessage(null)

        const result = await saveConfig(localConfig)

        if (result.success) {
            setSaveMessage({ type: 'success', text: i18n.t('Configuration saved successfully') })
        } else {
            setSaveMessage({ type: 'error', text: i18n.t('Failed to save configuration') })
        }

        setSaving(false)

        // Clear message after 3 seconds
        setTimeout(() => setSaveMessage(null), 3000)
    }

    const handleReset = async () => {
        setSaving(true)
        setSaveMessage(null)

        const result = await resetConfig()

        if (result.success) {
            setSaveMessage({ type: 'success', text: i18n.t('Configuration reset to defaults') })
        } else {
            setSaveMessage({ type: 'error', text: i18n.t('Failed to reset configuration') })
        }

        setSaving(false)

        // Clear message after 3 seconds
        setTimeout(() => setSaveMessage(null), 3000)
    }

    const handleExport = () => {
        try {
            const configJson = JSON.stringify(config, null, 2)
            const blob = new Blob([configJson], { type: 'application/json' })
            const url = URL.createObjectURL(blob)
            const link = document.createElement('a')
            link.href = url
            link.download = `security-auditor-config-${new Date().toISOString().split('T')[0]}.json`
            document.body.appendChild(link)
            link.click()
            document.body.removeChild(link)
            URL.revokeObjectURL(url)

            setSaveMessage({ type: 'success', text: i18n.t('Configuration exported successfully') })
            setTimeout(() => setSaveMessage(null), 3000)
        } catch (err) {
            setSaveMessage({ type: 'error', text: i18n.t('Failed to export configuration') })
            setTimeout(() => setSaveMessage(null), 3000)
        }
    }

    const handleImport = async (event) => {
        const file = event.target.files?.[0]
        if (!file) return

        setSaving(true)
        setSaveMessage(null)

        try {
            const text = await file.text()
            const importedConfig = JSON.parse(text)

            // Validate that imported config has expected structure
            const requiredKeys = ['minPasswordLength', 'maxInactiveMonths', 'maxPasswordAgeDays', 'maxSuperUserRoles']
            const hasAllKeys = requiredKeys.every(key => key in importedConfig)

            if (!hasAllKeys) {
                throw new Error('Invalid configuration file format')
            }

            // Validate that values are numbers
            const allNumbers = requiredKeys.every(key => typeof importedConfig[key] === 'number')
            if (!allNumbers) {
                throw new Error('Invalid configuration values')
            }

            const result = await saveConfig(importedConfig)

            if (result.success) {
                setLocalConfig(importedConfig)
                setSaveMessage({ type: 'success', text: i18n.t('Configuration imported successfully') })
            } else {
                setSaveMessage({ type: 'error', text: i18n.t('Failed to save imported configuration') })
            }
        } catch (err) {
            setSaveMessage({
                type: 'error',
                text: `${i18n.t('Failed to import configuration')}: ${err.message}`
            })
        } finally {
            setSaving(false)
            // Clear the file input
            if (fileInputRef.current) {
                fileInputRef.current.value = ''
            }
            // Clear message after 3 seconds
            setTimeout(() => setSaveMessage(null), 3000)
        }
    }

    const handleImportClick = () => {
        fileInputRef.current?.click()
    }

    if (loading) {
        return (
            <Card className={classes.card}>
                <CircularLoader />
            </Card>
        )
    }

    return (
        <>
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
                    label={i18n.t('Maximum Super User Roles')}
                    type="number"
                    min="1"
                    max="50"
                    value={String(localConfig.maxSuperUserRoles)}
                    onChange={({ value }) => handleChange('maxSuperUserRoles', value)}
                    helpText={i18n.t('Maximum number of user roles with ALL authorities before warning')}
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
    </>
    )
}
