import {
    DEFAULT_SCAN_LIMITS,
    SCAN_LIMIT_BOUNDS,
    resolveScanLimits,
} from './scanLimits'

const MB = 1024 * 1024

describe('resolveScanLimits', () => {
    it('falls back to the documented defaults when config is absent', () => {
        expect(resolveScanLimits()).toEqual({
            maxFiles: DEFAULT_SCAN_LIMITS.maxAppFilesScanned,
            maxTotalBytes: DEFAULT_SCAN_LIMITS.maxAppScanMb * MB,
            maxFileBytes: DEFAULT_SCAN_LIMITS.maxAppFileMb * MB,
            minEncodedLiteralLength:
                DEFAULT_SCAN_LIMITS.minEncodedLiteralLength,
            maxConsecutiveUnfetchable:
                DEFAULT_SCAN_LIMITS.maxConsecutiveUnfetchable,
            enableCodeAnalysis: DEFAULT_SCAN_LIMITS.enableCodeAnalysis,
        })
    })

    it('uses configured values over defaults', () => {
        const limits = resolveScanLimits({
            maxAppFilesScanned: 7,
            maxAppScanMb: 2,
            maxAppFileMb: 1,
            minEncodedLiteralLength: 0,
            maxConsecutiveUnfetchable: 3,
            enableCodeAnalysis: true,
        })
        expect(limits).toEqual({
            maxFiles: 7,
            maxTotalBytes: 2 * MB,
            maxFileBytes: 1 * MB,
            minEncodedLiteralLength: 0,
            maxConsecutiveUnfetchable: 3,
            enableCodeAnalysis: true,
        })
    })

    it('honours a configured zero rather than treating it as missing', () => {
        // Setting the literal threshold to 0 is the documented way to see
        // every encoded-literal finding; a falsy check would silently
        // restore the default instead.
        expect(resolveScanLimits({ minEncodedLiteralLength: 0 })
            .minEncodedLiteralLength).toBe(0)
    })

    it('ignores partial or malformed config entries', () => {
        const limits = resolveScanLimits({
            maxAppFilesScanned: 'lots',
            maxAppScanMb: NaN,
        })
        expect(limits.maxFiles).toBe(DEFAULT_SCAN_LIMITS.maxAppFilesScanned)
        expect(limits.maxTotalBytes).toBe(
            DEFAULT_SCAN_LIMITS.maxAppScanMb * MB
        )
    })
})

describe('SCAN_LIMIT_BOUNDS', () => {
    it('is off by default, and honours an explicit true', () => {
        // Default off: on minified bundles the analysis cannot support a
        // verdict, and it is the dominant cost of a scan.
        expect(resolveScanLimits().enableCodeAnalysis).toBe(false)
        expect(
            resolveScanLimits({ enableCodeAnalysis: true }).enableCodeAnalysis
        ).toBe(true)
    })

    it('covers every numeric default, and each sits inside its bounds', () => {
        const numericDefaults = Object.keys(DEFAULT_SCAN_LIMITS).filter(
            (key) => typeof DEFAULT_SCAN_LIMITS[key] === 'number'
        )
        expect(Object.keys(SCAN_LIMIT_BOUNDS).sort()).toEqual(
            numericDefaults.sort()
        )
        for (const [key, { min, max }] of Object.entries(SCAN_LIMIT_BOUNDS)) {
            expect(DEFAULT_SCAN_LIMITS[key]).toBeGreaterThanOrEqual(min)
            expect(DEFAULT_SCAN_LIMITS[key]).toBeLessThanOrEqual(max)
        }
    })
})
