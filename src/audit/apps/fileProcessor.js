import { suppressBenign } from './suppressBenign'
import { hashSource } from './hashSource'
import { findModuleImports } from './moduleImports'
import { scanFile as retireScanFile } from './retireScan'

// Everything the audit does to one file's source text, in one place.
//
// All of it is a pure function of a string: parse it, match library
// signatures against it, hash it, list its imports. That is what makes it
// portable to a Web Worker — this module runs unchanged on either side, and
// scanApp neither knows nor cares which thread it executed on.
//
// Splitting it out this way is also what keeps the fallback honest: if a
// Worker cannot be created, the same code runs on the main thread and the
// results are identical by construction rather than by careful duplication.

// Warning kinds that carry near-zero signal in practice and are dropped
// unconditionally. We tried gating these on js-x-ray's `isMinified` flag, but
// that heuristic stays false on many real React/Vite bundles whose surviving
// DOM/Fiber identifier names (focusedElem, selectionRange, containerInfo,
// parentNode, …) push the identifier-length average back up.
//
//   unsafe-assign  — fires on any `obj[someProperty] = value` shape. Hits
//                    React reconciler bookkeeping (e.alternate, c.stateNode,
//                    r.tag, …) and DOM property writes constantly. Measured:
//                    219 hits on an untouched react-dom production build.
//   unsafe-regex   — safe-regex star-height check; matches moment's ISO-8601
//                    parser and similar bounded-but-nested patterns shipped
//                    by date/parsing libs.
const NOISY_KINDS = new Set(['unsafe-assign', 'unsafe-regex'])

// Process one file.
//
// `skipAnalysis` covers the too-large case: the file is still hashed and
// still matched against the library signatures — both are cheap and neither
// needs a parser — while the expensive parse is skipped. Integrity and
// library detection should not lose coverage because a file is big.
//
// An analyzer failure is returned rather than thrown. js-x-ray 3.2.0 crashes
// outright on at least one real DHIS2 bundle, and that must cost the file's
// warnings, not the whole app.
export const processSource = async ({
    src,
    source,
    skipAnalysis,
    limits,
    repository,
    analyze,
}) => {
    const hash = await hashSource(source)
    const libraries = repository
        ? retireScanFile({ src, content: source }, repository)
        : []
    const imports = findModuleImports(source)

    if (skipAnalysis || typeof analyze !== 'function') {
        return { hash, libraries, imports }
    }

    try {
        const result = analyze(source)
        const warnings = suppressBenign(
            (result?.warnings || []).filter((w) => !NOISY_KINDS.has(w.kind)),
            source,
            limits
        )
        return {
            hash,
            libraries,
            imports,
            warnings,
            isMinified: !!result?.isMinified,
        }
    } catch (err) {
        return {
            hash,
            libraries,
            imports,
            analyzeError: err.message || String(err),
        }
    }
}

// Build a processor that runs on whichever thread calls it. `analyze` is
// resolved once and closed over, so the analyzer module is loaded a single
// time per run rather than per file.
export const createInThreadProcessor = ({ analyze, repository, limits }) => (
    request
) => processSource({ ...request, limits, repository, analyze })
