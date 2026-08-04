// Single source of truth for the bounds the apps scan operates under.
//
// These are user-configurable rather than baked in: what counts as a
// reasonable ceiling depends on the instance (how many apps, how large, how
// much main-thread time an admin is willing to spend), and a hidden constant
// that silently drops files is exactly the kind of thing that makes an audit
// report look more complete than it is. Anything the scan skips because of
// one of these is reported in the findings.
//
// DEFAULT_SCAN_LIMITS is merged into DEFAULT_CONFIG (useAuditConfig) and the
// bounds are enforced by configValidation, so the same numbers drive the
// dataStore config, the Configuration panel inputs and the import validator.
//
// Every default below is justified against a measurement taken on DHIS2
// 2.43.1 (play.im.dhis2.org), scanning eight production apps — dashboard,
// maps, user, data-visualizer, capture, scheduler, import-export, settings.
// Where a number is a judgement call inside a range rather than something the
// data pins down, that is said explicitly.
export const DEFAULT_SCAN_LIMITS = {
    // Files fetched and analyzed per app, across the whole module graph.
    //
    // Measured files per app: 2, 2, 2, 2, 2, 4, 5, 5 — max 5.
    // 40 is ~8x the observed maximum. The headroom covers apps that
    // code-split more aggressively than any current DHIS2 app; the ceiling
    // exists only so a pathological or hostile module graph (a chunk that
    // imports a fresh generated name each time) cannot spin the scan
    // forever. Any value from ~10 upwards would scan every real app in full.
    maxAppFilesScanned: 40,

    // Total bytes analyzed per app.
    //
    // Measured totals per app: 1.3, 1.8, 1.9, 2.8, 2.9, 4.4, 6.5, 7.2 MB —
    // max 7.2 MB. 24 MB is ~3.3x the observed maximum, so no current app is
    // truncated. Same rationale as above: a bound on runaway work, not a
    // filter on real apps.
    maxAppScanMb: 24,

    // Per-file ceiling. Unchanged from the value this scanner already used.
    //
    // This is the one limit that currently excludes real code: capture's
    // 6.4 MB chunk exceeds it. Raising it does not help, and that is
    // measured, not assumed — the pinned js-x-ray 3.2.0 throws on that exact
    // file (TypeError in its isRequire probe), which would mark the app
    // errored rather than scanned, and the maintained successor takes ~47 s
    // on it. js-x-ray parses on the browser's main thread, so a single very
    // large chunk is what actually stalls the UI. Kept at 5 MB, and the skip
    // is reported in the findings rather than hidden.
    maxAppFileMb: 5,

    // Shortest `encoded-literal` value still worth reporting.
    //
    // Every false positive observed on live bundles was 5 characters: the
    // i18next event name "added", and DHIS2 error codes such as "E7113" —
    // eleven of the latter in a single data-visualizer chunk. Base64 encodes
    // 3 bytes as 4 characters, so 16 characters is about 12 decoded bytes:
    // long enough that a genuinely encoded payload clears it, short enough
    // that it is not doing much filtering.
    //
    // Honest caveat: the data only says "above 5", so anything from roughly
    // 8 to 24 would have behaved identically on these bundles. 16 is a
    // judgement call in that range, which is part of why it is configurable.
    minEncodedLiteralLength: 16,
}

// Bounds for each limit, shared by configValidation and the Configuration
// panel's input fields. Deliberately wide — they exist to catch nonsense
// (negative, zero, absurd) rather than to second-guess the operator.
export const SCAN_LIMIT_BOUNDS = {
    maxAppFilesScanned: { min: 1, max: 500 },
    maxAppScanMb: { min: 1, max: 256 },
    maxAppFileMb: { min: 1, max: 64 },
    minEncodedLiteralLength: { min: 0, max: 128 },
}

const MB = 1024 * 1024

// Resolve a (possibly partial or absent) config into concrete limits. Callers
// in the scan path use this so a missing key falls back to the documented
// default rather than to zero.
export const resolveScanLimits = (config = {}) => {
    const pick = (key) => {
        const value = config?.[key]
        return typeof value === 'number' && Number.isFinite(value)
            ? value
            : DEFAULT_SCAN_LIMITS[key]
    }
    return {
        maxFiles: pick('maxAppFilesScanned'),
        maxTotalBytes: pick('maxAppScanMb') * MB,
        maxFileBytes: pick('maxAppFileMb') * MB,
        minEncodedLiteralLength: pick('minEncodedLiteralLength'),
    }
}
