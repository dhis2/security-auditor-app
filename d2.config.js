/** @type {import('@dhis2/cli-app-scripts').D2Config} */
const config = {
    type: 'app',
    name: 'security-auditor-app',
    title: 'Security Auditor',

    // Shown under "About this app" in the App Management app. For a manually
    // uploaded app this is read straight from manifest.webapp, and App
    // Management renders it through react-markdown -- so markdown works.
    // Overrides the (single-line) description in package.json.
    description: `Read-only security auditing for a DHIS2 instance. Intended for system administrators and security reviewers.

**DHIS2 Audit** — checks instance configuration, user accounts, roles and authorities, and HTTP response headers. Surfaces common misconfigurations: weak password policies, over-privileged roles, dormant accounts, missing security headers and unsafe CORS settings.

**Apps Audit** — downloads the JavaScript of every installed app, analyses it locally for obfuscated or otherwise suspicious code, matches dependencies against Retire.js vulnerability signatures, and compares file hashes against a recorded integrity baseline to detect app code that changed without a version change.

Both audits run entirely in the browser using the current user's session — no instance data is sent anywhere. Findings can be exported as a self-contained HTML report.

Requires DHIS2 v40+ and the \`ALL\` or \`F_SYSTEM_SETTING\` authority. HTTPS is required for the Apps Audit integrity baseline (Web Crypto is only available in a secure context).`,

    entryPoints: {
        app: './src/App.jsx',
    },

    direction: 'auto',
}

module.exports = config
