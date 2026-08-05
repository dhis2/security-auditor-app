import { Buffer } from 'buffer'

// Side-effecting: installs Buffer before js-x-ray is evaluated.
//
// js-x-ray's sec-literal dependency uses Node's Buffer for base64 inspection
// and captures the global when its module body runs. Browsers have no Buffer,
// so it must be in place first — which is why this is a separate module
// imported ahead of js-x-ray rather than a statement in the same file. ES
// modules evaluate in import order, so importing this first is the guarantee;
// two statements in one module would not be, because all imports are hoisted
// above the code.
if (typeof globalThis.Buffer === 'undefined') {
    globalThis.Buffer = Buffer
}
