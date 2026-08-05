import { expandVersionPlaceholders } from './retireScan'

// Lazy-loaded accessor for the Retire.js signature repository.
//
// Two possible sources:
//   - the copy vendored at build time, which always works offline
//   - a set downloaded on demand and kept in the dataStore
//
// Whichever was retrieved more recently wins, so a downloaded set keeps being
// used until a newer app build overtakes it, and an old download never
// shadows fresher vendored data.
//
// The vendored JSON is ~380 KB, so it is kept out of the main bundle and
// pulled in only when an apps audit runs — the same treatment js-x-ray gets
// in utils/jsXRay.js.
let vendoredPromise = null

const loadVendored = () => {
    if (!vendoredPromise) {
        vendoredPromise = (async () => {
            const module = await import('./retireRepository.json')
            return module.default || module
        })()
    }
    return vendoredPromise
}

// Retrieval dates are compared as instants. The vendored file records a date
// only (YYYY-MM-DD); a downloaded set records a full timestamp. Date.parse
// handles both, and a same-day download sorts after the build's date, which
// is the behaviour we want.
const retrievedTime = (document) => {
    const parsed = Date.parse(document?.retrievedAt ?? '')
    return Number.isNaN(parsed) ? -Infinity : parsed
}

// `stored` is the signature set from the dataStore, or null. Placeholders are
// expanded once here rather than per file scanned: the expansion walks every
// pattern in every component, and an audit scans dozens of files.
export const getRetireRepository = async ({ stored } = {}) => {
    const vendored = await loadVendored()
    const chosen =
        stored?.components && retrievedTime(stored) > retrievedTime(vendored)
            ? { ...stored, origin: 'downloaded' }
            : { ...vendored, origin: 'bundled' }

    return {
        retrievedAt: chosen.retrievedAt,
        source: chosen.source,
        origin: chosen.origin,
        components: expandVersionPlaceholders(chosen.components),
    }
}

// Test seam: drop the memoized vendored copy so a test can supply its own.
export const __setVendoredRepositoryForTests = (repository) => {
    vendoredPromise = repository ? Promise.resolve(repository) : null
}
