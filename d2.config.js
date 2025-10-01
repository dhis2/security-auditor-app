/** @type {import('@dhis2/cli-app-scripts').D2Config} */
const config = {
    type: 'app',
    name: 'security-auditor-app',
    title: 'Security Auditor',
    entryPoints: {
        app: './src/App.jsx',
    },

    direction: 'auto',
}

module.exports = config
