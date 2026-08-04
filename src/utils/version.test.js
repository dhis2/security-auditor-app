import { parseDhis2Version, passwordLastUpdatedField } from './version'

describe('parseDhis2Version', () => {
    it('parses legacy "2.X.Y" format and returns the second component as major', () => {
        expect(parseDhis2Version('2.42.0')).toEqual({ major: 42, raw: '2.42.0' })
        expect(parseDhis2Version('2.39.1')).toEqual({ major: 39, raw: '2.39.1' })
    })

    it('parses post-2.x format where the leading 2 is dropped', () => {
        expect(parseDhis2Version('42.0.0')).toEqual({ major: 42, raw: '42.0.0' })
    })

    it('returns null for missing or empty input', () => {
        expect(parseDhis2Version()).toBeNull()
        expect(parseDhis2Version(null)).toBeNull()
        expect(parseDhis2Version('')).toBeNull()
    })

    it('returns null when no numeric components are parseable', () => {
        expect(parseDhis2Version('not-a-version')).toBeNull()
    })
})

describe('passwordLastUpdatedField', () => {
    it('uses the flat field on v42+', () => {
        expect(passwordLastUpdatedField({ major: 42 })).toBe('passwordLastUpdated')
        expect(passwordLastUpdatedField({ major: 43 })).toBe('passwordLastUpdated')
    })

    it('uses the legacy nested field on pre-v42', () => {
        expect(passwordLastUpdatedField({ major: 41 })).toBe(
            'userCredentials.passwordLastUpdated'
        )
        expect(passwordLastUpdatedField({ major: 39 })).toBe(
            'userCredentials.passwordLastUpdated'
        )
    })

    it('falls back to the legacy field when version is unknown', () => {
        expect(passwordLastUpdatedField(null)).toBe(
            'userCredentials.passwordLastUpdated'
        )
        expect(passwordLastUpdatedField(undefined)).toBe(
            'userCredentials.passwordLastUpdated'
        )
    })
})
