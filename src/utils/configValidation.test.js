import { validateConfig, REQUIRED_CONFIG_KEYS } from './configValidation'

const validConfig = {
    minPasswordLength: 8,
    maxInactiveMonths: 3,
    maxPasswordAgeDays: 365,
    maxSuperUserRoles: 5,
}

describe('validateConfig', () => {
    it('returns no errors for a valid config', () => {
        expect(validateConfig(validConfig)).toEqual([])
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
            minPasswordLength: -1,
            maxInactiveMonths: 'three',
            maxPasswordAgeDays: 365,
            maxSuperUserRoles: 5,
        })
        expect(errors).toHaveLength(2)
    })
})

describe('REQUIRED_CONFIG_KEYS', () => {
    it('lists exactly the four expected keys', () => {
        expect(REQUIRED_CONFIG_KEYS).toEqual([
            'minPasswordLength',
            'maxInactiveMonths',
            'maxPasswordAgeDays',
            'maxSuperUserRoles',
        ])
    })
})
