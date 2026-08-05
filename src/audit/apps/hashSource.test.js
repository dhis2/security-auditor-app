import { installWebCrypto, removeWebCrypto } from '../../testUtils/webCrypto'
import { hashSource, hashingAvailable } from './hashSource'

describe('hashSource', () => {
    it('produces the known SHA-256 of a known input', async () => {
        const restore = installWebCrypto()
        try {
            expect(hashingAvailable()).toBe(true)
            expect(await hashSource('abc')).toBe(
                'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
            )
        } finally {
            restore()
        }
    })

    it('pads single-digit bytes so digests are a fixed 64 hex chars', async () => {
        const restore = installWebCrypto()
        try {
            // A digest containing a byte < 0x10 formats wrong if padStart is
            // dropped, which would silently break every comparison.
            expect(await hashSource('')).toBe(
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            )
        } finally {
            restore()
        }
    })

    it('hashes non-ASCII consistently', async () => {
        const restore = installWebCrypto()
        try {
            expect(await hashSource('café — ☕')).toMatch(/^[0-9a-f]{64}$/)
        } finally {
            restore()
        }
    })

    it('returns null rather than throwing when Web Crypto is missing', async () => {
        // Plain-HTTP DHIS2 instances have no secure context. Integrity is
        // then unknown, which callers report as such.
        const restore = removeWebCrypto()
        try {
            expect(hashingAvailable()).toBe(false)
            expect(await hashSource('abc')).toBeNull()
        } finally {
            restore()
        }
    })

    it('returns null for non-string input', async () => {
        const restore = installWebCrypto()
        try {
            expect(await hashSource(undefined)).toBeNull()
            expect(await hashSource(42)).toBeNull()
        } finally {
            restore()
        }
    })
})
