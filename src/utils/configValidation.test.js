import { DEFAULT_SCAN_LIMITS } from '../audit/apps/scanLimits'
import { DEFAULT_CONFIG } from '../hooks/useAuditConfig'
import { validateConfig, REQUIRED_CONFIG_KEYS } from './configValidation'

const validConfig = {
    minPasswordLength: 8,
    maxInactiveMonths: 3,
    maxPasswordAgeDays: 365,
    maxSuperUserRoles: 5,
    maxAuditPages: 5000,
    maxAppAuditConcurrency: 4,
    ...DEFAULT_SCAN_LIMITS,
}

describe('validateConfig', () => {
    it('returns no errors for a valid config', () => {
        expect(validateConfig(validConfig)).toEqual([])
    })

    it('accepts the shipped defaults', () => {
        // Guards against a new key being added to DEFAULT_CONFIG with a
        // default that falls outside its own validation bounds.
        expect(validateConfig(DEFAULT_CONFIG)).toEqual([])
    })

    it('reports a non-object as a single error', () => {
        expect(validateConfig(null)).toEqual(['Configuration must be an object'])
        expect(validateConfig('not an object')).toEqual([
            'Configuration must be an object',
        ])
    })

    it('catches NaN values (the cleared-input case)', () => {
        const errors = validateConfig({ ...validConfig, minPasswordLength: NaN })
        expect(errors).toContain('Minimum password length must be a number')
    })

    it('catches non-integer values', () => {
        const errors = validateConfig({ ...validConfig, maxInactiveMonths: 1.5 })
        expect(errors).toContain('Maximum inactive months must be a whole number')
    })

    it('catches values below the minimum', () => {
        const errors = validateConfig({ ...validConfig, maxPasswordAgeDays: 0 })
        expect(errors).toContain(
            'Maximum password age (days) must be between 30 and 1095'
        )
    })

    it('catches values above the maximum', () => {
        const errors = validateConfig({
            ...validConfig,
            maxSuperUserRoles: 99999,
        })
        expect(errors).toContain(
            'Maximum users with privileged authorities must be between 1 and 50'
        )
    })

    it('reports multiple errors at once', () => {
        const errors = validateConfig({
            ...validConfig,
            minPasswordLength: -1,
            maxInactiveMonths: 'three',
        })
        expect(errors).toHaveLength(2)
    })
})

describe('REQUIRED_CONFIG_KEYS', () => {
    it('lists exactly the expected keys', () => {
        expect(REQUIRED_CONFIG_KEYS).toEqual([
            'minPasswordLength',
            'maxInactiveMonths',
            'maxPasswordAgeDays',
            'maxSuperUserRoles',
            'maxAuditPages',
            'maxAppAuditConcurrency',
            'maxAppFilesScanned',
            'maxAppScanMb',
            'maxAppFileMb',
            'minEncodedLiteralLength',
            'retireMaxAgeMinutes',
        ])
    })

    it('validates every key the app ships a default for', () => {
        // A default with no validation rule silently bypasses the bounds
        // check on import.
        expect(REQUIRED_CONFIG_KEYS.sort()).toEqual(
            Object.keys(DEFAULT_CONFIG).sort()
        )
    })
})

describe('maxAuditPages', () => {
    it('rejects values below the minimum', () => {
        const errors = validateConfig({ ...validConfig, maxAuditPages: 50 })
        expect(errors).toContain(
            'Maximum audit pages per query must be between 100 and 50000'
        )
    })

    it('rejects values above the maximum', () => {
        const errors = validateConfig({ ...validConfig, maxAuditPages: 100000 })
        expect(errors).toContain(
            'Maximum audit pages per query must be between 100 and 50000'
        )
    })

    it('accepts values inside the bounds', () => {
        expect(validateConfig({ ...validConfig, maxAuditPages: 5000 })).toEqual([])
    })
})
