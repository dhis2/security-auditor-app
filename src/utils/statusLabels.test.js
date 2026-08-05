import { reportStatusLabel, statusLabel } from './statusLabels'

describe('status labels', () => {
    it('shows `fail` as "Risk", not "Fail"', () => {
        // "Fail" reads as either "the system has a problem" or "the check did
        // not run". Those need different responses, and `error` already means
        // the second one.
        expect(statusLabel('fail')).toBe('Risk')
        expect(reportStatusLabel('fail')).toBe('RISK')
    })

    it('keeps `error` distinct, for a check that could not complete', () => {
        expect(statusLabel('error')).toBe('Error')
        expect(reportStatusLabel('error')).toBe('ERROR')
    })

    it('labels the remaining statuses', () => {
        expect(statusLabel('pass')).toBe('Pass')
        expect(statusLabel('warning')).toBe('Warning')
        expect(statusLabel('info')).toBe('Info')
        expect(statusLabel('running')).toBe('Running')
    })

    it('falls back rather than rendering undefined', () => {
        expect(statusLabel('nonsense')).toBe('Unknown')
        expect(reportStatusLabel(undefined)).toBe('UNKNOWN')
    })
})
