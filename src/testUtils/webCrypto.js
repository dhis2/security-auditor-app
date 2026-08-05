// Test-only helper: give jsdom the Web Crypto pieces real browsers have.
//
// Jest's jsdom environment ships neither `crypto.subtle` nor `TextEncoder`,
// both of which every browser DHIS2 supports has had for years. Without this
// the integrity hashing silently degrades to "unavailable" under test and the
// baseline tests would pass while asserting nothing.
//
// d2-app-scripts owns the jest config and exposes no setupFiles hook, so
// tests opt in explicitly:
//
//   const restore = installWebCrypto()
//   ...
//   restore()
export const installWebCrypto = () => {
    const previousCrypto = globalThis.crypto
    const previousEncoder = globalThis.TextEncoder

    // eslint-disable-next-line no-undef
    const { webcrypto } = require('node:crypto')
    // eslint-disable-next-line no-undef
    const { TextEncoder } = require('node:util')

    globalThis.crypto = webcrypto
    globalThis.TextEncoder = TextEncoder

    return () => {
        globalThis.crypto = previousCrypto
        globalThis.TextEncoder = previousEncoder
    }
}

// The inverse: prove the plain-HTTP path, where there is no secure context.
export const removeWebCrypto = () => {
    const previousCrypto = globalThis.crypto
    const previousEncoder = globalThis.TextEncoder
    globalThis.crypto = undefined
    globalThis.TextEncoder = undefined
    return () => {
        globalThis.crypto = previousCrypto
        globalThis.TextEncoder = previousEncoder
    }
}
