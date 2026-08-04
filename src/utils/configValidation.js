import i18n from '@dhis2/d2-i18n'
import { SCAN_LIMIT_BOUNDS } from '../audit/apps/scanLimits'

// Bounds for each numeric config field. The same constraints are applied
// when saving from the UI (handles NaN from cleared inputs) and when
// importing a JSON config file. These bounds must match the `min`/`max`
// attributes on the corresponding InputField in ConfigurationPanel.jsx.
//
// `getLabel` returns the translated label; we hold the i18n call inside a
// thunk so the bounds object can be defined at module load (before i18n
// resources are necessarily ready) without freezing the English label.
const RULES = {
    minPasswordLength: {
        getLabel: () => i18n.t('Minimum password length'),
        min: 1,
        max: 50,
    },
    maxInactiveMonths: {
        getLabel: () => i18n.t('Maximum inactive months'),
        min: 1,
        max: 24,
    },
    maxPasswordAgeDays: {
        getLabel: () => i18n.t('Maximum password age (days)'),
        min: 30,
        max: 1095,
    },
    maxSuperUserRoles: {
        getLabel: () => i18n.t('Maximum users with privileged authorities'),
        min: 1,
        max: 50,
    },
    maxAuditPages: {
        getLabel: () => i18n.t('Maximum audit pages per query'),
        min: 100,
        max: 50000,
    },
    maxAppAuditConcurrency: {
        getLabel: () => i18n.t('Apps audit concurrency'),
        min: 1,
        max: 16,
    },
    maxAppFilesScanned: {
        getLabel: () => i18n.t('Maximum files scanned per app'),
        ...SCAN_LIMIT_BOUNDS.maxAppFilesScanned,
    },
    maxAppScanMb: {
        getLabel: () => i18n.t('Maximum MB scanned per app'),
        ...SCAN_LIMIT_BOUNDS.maxAppScanMb,
    },
    maxAppFileMb: {
        getLabel: () => i18n.t('Maximum MB per app file'),
        ...SCAN_LIMIT_BOUNDS.maxAppFileMb,
    },
    minEncodedLiteralLength: {
        getLabel: () => i18n.t('Minimum encoded literal length reported'),
        ...SCAN_LIMIT_BOUNDS.minEncodedLiteralLength,
    },
}

export const REQUIRED_CONFIG_KEYS = Object.keys(RULES)

// Validate a config object. Returns an array of human-readable error messages;
// an empty array means the config is valid.
export const validateConfig = (config) => {
    const errors = []
    if (!config || typeof config !== 'object') {
        return [i18n.t('Configuration must be an object')]
    }
    for (const key of REQUIRED_CONFIG_KEYS) {
        const rule = RULES[key]
        const label = rule.getLabel()
        const value = config[key]
        if (typeof value !== 'number' || !Number.isFinite(value)) {
            errors.push(i18n.t('{{label}} must be a number', { label }))
            continue
        }
        if (!Number.isInteger(value)) {
            errors.push(i18n.t('{{label}} must be a whole number', { label }))
            continue
        }
        if (value < rule.min || value > rule.max) {
            errors.push(
                i18n.t('{{label}} must be between {{min}} and {{max}}', {
                    label,
                    min: rule.min,
                    max: rule.max,
                })
            )
        }
    }
    return errors
}
