#!/usr/bin/env node
/*
 * Refresh the vendored Retire.js signature repository.
 *
 *   node scripts/update-retire-repository.js
 *
 * Why vendored rather than fetched at runtime: the Apps Audit promises that
 * nothing leaves the DHIS2 instance, and many instances that most need an
 * audit are the ones without outbound internet access. A build-time copy
 * keeps the scan offline and deterministic. The cost is staleness, so the
 * fetch date is recorded in the file and shown in the UI and the report —
 * an out-of-date signature set should be visible, not silent.
 *
 * What is dropped, and why:
 *   func  — evaluates an expression against a *running* library instance.
 *   ast   — needs retire.js's own AST query engine over a parsed file.
 * Neither is usable here, and together they are a large share of the bytes.
 *
 * Retire.js and this repository data are Apache-2.0 licensed.
 * Upstream: https://github.com/RetireJS/retire.js
 */
const fs = require('node:fs')
const path = require('node:path')

const SOURCE_URL =
    'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v3.json'

const OUTPUT = path.join(
    __dirname,
    '..',
    'src',
    'audit',
    'apps',
    'retireRepository.json'
)

// Extractors this scanner can actually evaluate against a fetched file.
const USABLE_EXTRACTORS = [
    'filename',
    'filecontent',
    'filecontentreplace',
    'uri',
    'hashes',
]

const pruneComponent = (entry) => {
    const extractors = {}
    for (const kind of USABLE_EXTRACTORS) {
        const value = entry.extractors?.[kind]
        if (!value) {
            continue
        }
        const empty = Array.isArray(value)
            ? value.length === 0
            : Object.keys(value).length === 0
        if (!empty) {
            extractors[kind] = value
        }
    }
    if (Object.keys(extractors).length === 0) {
        return null
    }
    const vulnerabilities = (entry.vulnerabilities || []).map((v) => ({
        ...(v.below !== undefined && { below: v.below }),
        ...(v.atOrAbove !== undefined && { atOrAbove: v.atOrAbove }),
        ...(v.excludes !== undefined && { excludes: v.excludes }),
        ...(v.severity !== undefined && { severity: v.severity }),
        ...(v.cwe !== undefined && { cwe: v.cwe }),
        ...(v.identifiers !== undefined && { identifiers: v.identifiers }),
        ...(v.info !== undefined && { info: v.info }),
    }))
    return {
        ...(entry.npmname && { npmname: entry.npmname }),
        extractors,
        vulnerabilities,
    }
}

const main = async () => {
    process.stdout.write(`Fetching ${SOURCE_URL}\n`)
    const response = await fetch(SOURCE_URL)
    if (!response.ok) {
        throw new Error(`HTTP ${response.status} fetching the repository`)
    }
    const upstream = await response.json()
    const advisories = upstream.advisories || upstream

    const components = {}
    let dropped = 0
    for (const [name, entry] of Object.entries(advisories)) {
        // Upstream ships a self-test entry that matches nothing real.
        if (name === 'retire-example') {
            continue
        }
        const pruned = pruneComponent(entry)
        if (pruned) {
            components[name] = pruned
        } else {
            dropped += 1
        }
    }

    const document = {
        // Provenance, so a reader of the JSON knows what it is and how old.
        source: SOURCE_URL,
        license: 'Apache-2.0',
        upstream: 'https://github.com/RetireJS/retire.js',
        retrievedAt: new Date().toISOString().slice(0, 10),
        components,
    }

    fs.writeFileSync(OUTPUT, JSON.stringify(document, null, 0) + '\n')
    const kb = (fs.statSync(OUTPUT).size / 1024).toFixed(0)
    process.stdout.write(
        `Wrote ${Object.keys(components).length} components (${dropped} had no usable extractor) to ${OUTPUT} — ${kb} KB\n`
    )
}

main().catch((err) => {
    process.stderr.write(`${err.message}\n`)
    process.exit(1)
})
