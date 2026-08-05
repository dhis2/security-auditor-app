// Constructing the scan worker, isolated in its own module.
//
// `import.meta.url` is the only portable way to point a bundler at a worker
// entry, and it is also syntax that the CommonJS transform used for tests
// cannot parse. Keeping it here means the module is only ever loaded behind a
// `typeof Worker !== 'undefined'` check — under jsdom, which has no Worker,
// it is never imported at all and the main-thread fallback is used instead.
export const spawnScanWorker = () =>
    new Worker(new URL('./scanWorker.js', import.meta.url), {
        type: 'module',
    })
