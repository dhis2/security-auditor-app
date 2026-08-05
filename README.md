This project was bootstrapped with [DHIS2 Application Platform](https://github.com/dhis2/app-platform).

## Overview

The Security Auditor is a DHIS2 application that performs read-only security checks against your DHIS2 instance and reports findings. It is intended for system administrators and security reviewers and helps surface common misconfigurations: weak password policies, over-privileged user roles, missing security headers, unsafe CORS configuration, dormant accounts, and similar issues.

It has two independent audits:

- **DHIS2 Audit** — configuration, user/authority and HTTP header checks against the instance.
- **Apps Audit** — fetches the JavaScript of every installed app, analyzes it locally for obfuscated or otherwise suspicious code, and compares file hashes against a recorded integrity baseline to detect app code that changed without a version change.

Both audits run entirely client-side — no instance data leaves your DHIS2 server. All checks use the standard DHIS2 Web API via the authenticated session of the currently logged-in user, with two exceptions that still only talk to your own server: the default-admin-credentials check sends a request *without* the session cookie, and the Apps Audit downloads app bundles from the instance for local analysis.

There is exactly one request to a third party. Starting an Apps Audit downloads the current [Retire.js](https://github.com/RetireJS/retire.js) vulnerability signatures from `raw.githubusercontent.com` when the stored copy is older than the configured window (one hour by default); a "Fetch latest signatures" button does the same on demand. The request sends nothing about your instance — it is a plain GET for a public file — and the downloaded set is cached in the DHIS2 dataStore so other administrators do not repeat it. If it fails for any reason the audit continues with the most recent signatures available, falling back to the copy bundled into the app at build time. Set **Vulnerability Signature Max Age** to `0` in the Configuration tab to stop scans from reaching out automatically; the bundled signatures still apply.

## Requirements

- DHIS2 server **v40 or later**. Behaviour has been verified against 2.40.12, 2.41.9, 2.42.5.1 and 2.43.1.
- The user running the audit must hold the `ALL` authority **or** the `F_SYSTEM_SETTING` authority.
- A modern browser (Chrome/Firefox/Edge/Safari, current versions).
- **HTTPS** for the Apps Audit integrity baseline. File hashing uses Web Crypto, which browsers only expose in a secure context; over plain HTTP the scan still runs but integrity is reported as unknown.

A handful of checks rely on settings that are only present on newer DHIS2 versions (e.g. `enforceVerifiedEmail` was introduced in v42). On older instances those checks report as a warning labelled "not available on this DHIS2 version" rather than as an error.

## Installation

### From a release
1. Download the `.zip` from the [latest release](https://github.com/dhis2/security-auditor-app/releases).
2. In DHIS2, go to **App Management** → **Upload app** and select the `.zip`.
3. Open **Security Auditor** from the app menu.

### From source
```bash
yarn install
yarn build
yarn deploy   # prompts for server URL and admin credentials
```
The `yarn deploy` command requires a DHIS2 user with the **App Management** authority.

## Usage

1. Open the **Security Auditor** app from the DHIS2 app menu.
2. (Optional) Open the **Configuration** tab to adjust thresholds and scan limits. See [Configuration](#configuration) below.
3. On the **DHIS2 Audit** tab, click **Start DHIS2 Audit**. Checks run as their data arrives and the table updates continuously; findings are ordered failures → warnings → errors → passes.
4. On the **Apps Audit** tab, click **Start Apps Audit** to scan installed apps. See [Apps Audit](#apps-audit) below.
5. Click **Save Report** on either tab to download a self-contained HTML report you can share with stakeholders.
6. The **System Info** tab shows the DHIS2 version and build, server URL and system ID, OS/Java/servlet/database details, the detected web server, and the Security Auditor version that produced the report.
7. The **Console** tab shows the raw API responses collected by the DHIS2 Audit, useful for debugging or producing evidence.

## Configuration

Settings are stored per-instance in the DHIS2 dataStore (namespace `security-auditor-app`, key `config`). The entry is created lazily on the first save — until then the defaults below are used in memory.

| Setting                    | Default | Used by                                                                    |
| -------------------------- | ------- | -------------------------------------------------------------------------- |
| `minPasswordLength`        | 8       | Password Policy Configuration                                              |
| `maxInactiveMonths`        | 3       | Inactive User Accounts                                                     |
| `maxPasswordAgeDays`       | 365     | Password Age Verification                                                  |
| `maxSuperUserRoles`        | 5       | Threshold for "too many users with a privileged authority"                 |
| `maxAuditPages`            | 5000    | Hard cap on pages fetched per paged audit query (200 rows per page)        |
| `maxAppAuditConcurrency`   | 4       | Apps scanned in parallel by the Apps Audit                                 |
| `maxAppFilesScanned`       | 40      | Files fetched and analyzed per app, across its whole module graph          |
| `maxAppScanMb`             | 24      | Total megabytes analyzed per app                                           |
| `maxAppFileMb`             | 5       | Largest single file the analyzer will parse                                |
| `minEncodedLiteralLength`  | 16      | Shortest `encoded-literal` finding still worth reporting                   |

Edit values in the **Configuration** tab and click **Save Configuration**; **Reset to Defaults** restores the table above. Changes apply on the next audit run. Anything the Apps Audit skips because of one of the scan limits is listed in that app's findings rather than dropped silently — see `src/audit/apps/scanLimits.js` for the measurement behind each default.

The panel also supports **Export Configuration** / **Import Configuration** as JSON. Imports are validated against the allowed bounds, and keys missing from an older export are filled in from the current defaults.

## Checks performed

User & role checks:
- **Users With ALL Authority** — flags if too many users hold the unrestricted `ALL` authority.
- **Users Who Can Add Public Routes** — flags users with `F_PUBLIC_ROUTE_ADD`.
- **Users Who Can Impersonate Others** — flags users with `F_IMPERSONATE_USER`.
- **Users Who Can Change System Settings** — flags users with `F_SYSTEM_SETTING`.
- **Users Never Logged In** — surfaces active accounts that have never been used.
- **Inactive User Accounts** — surfaces active accounts inactive longer than the configured threshold.
- **Password Age Verification** — flags users whose passwords exceed the configured maximum age or were never set.
- **Default Admin Credentials Active Check** — actively tests whether the server still accepts `admin`/`district`. The request is sent without the current session cookie, so it neither uses nor disturbs your session.

Server policy checks:
- **Password Policy Configuration** — verifies `minPasswordLength` meets the configured minimum.
- **Password Expiry Policy** — flags if `credentialsExpires` is disabled.
- **Email Verification Enforcement** — flags if `enforceVerifiedEmail` is not `true` (DHIS2 v42+).
- **Account Lockout Policy** — flags if `lockMultipleFailedLogins` is not enabled.
- **CORS Whitelist Configuration** — flags wildcards or a populated whitelist on `configuration/corsWhitelist`.

Transport & header checks (read from the response headers of a request to the DHIS2 server):
- **HTTPS Connection Security** — fails if the app is served over plain HTTP.
- **HTTP Strict Transport Security (HSTS)** — checks the `Strict-Transport-Security` header, including whether `max-age` is present, valid and long enough.
- **Server Header Exposure** — flags if the server discloses its identity via the `Server` header.
- **Cross-Origin-Opener-Policy (COOP)** — checks the `Cross-Origin-Opener-Policy` header.
- **Cross-Origin-Embedder-Policy (COEP)** — checks the `Cross-Origin-Embedder-Policy` header.
- **Cross-Origin-Resource-Policy (CORP)** — checks the `Cross-Origin-Resource-Policy` header.
- **CORS Headers Configuration** — flags unsafe `Access-Control-Allow-Origin` values.
- **Content Security Policy (CSP)** — checks for a present, sane `Content-Security-Policy` header.

Installed app checks:
- **Installed App Sources** — classifies every installed app as bundled, App Hub or manually installed, and warns about anything sideloaded (no upstream review or signing).

## Apps Audit

The Apps Audit is a separate tab with its own run button and its own HTML report. For each installed app it:

1. Fetches the app's entry HTML (bypassing the DHIS2 2.42+ app shell) and follows its module graph — entry scripts, modulepreloads and lazy-loaded chunks — up to the configured file/size limits.
2. Analyzes each file with [js-x-ray](https://github.com/NodeSecure/js-x-ray) and reduces the warnings to a status of `fail`, `warning`, `info`, `pass` or `error`. The mapping is calibrated against known-good DHIS2 bundles: only a positive obfuscator fingerprint fails an app, while minification artefacts that fire on every bundle ever shipped (`unsafe-stmt`, `short-identifiers`, short `encoded-literal` values) are reported as observations. `src/audit/apps/classifyFindings.js` documents the measurements behind every choice.
3. Hashes each file with SHA-256 and compares it to the **integrity baseline**.

### Integrity baseline

The baseline is stored in the dataStore (namespace `security-auditor-app`, key `apps-baseline`) and holds only app keys, versions, file paths and hashes — nothing about the instance's data. Each app is reported as `new`, `unchanged`, `updated`, `drift` or `unknown`. Only **drift** — the same version with different content — fails the app: an app whose version moved was simply updated, but one whose bundle changed while claiming the same version was modified in place.

Baselines are never written automatically. Click **Record baseline** (or **Accept current state as baseline** once one exists) to record the current state as trusted; a baseline that refreshed itself after every run would quietly bless an attacker's code.

## Troubleshooting

- **"Administrator Access Required" on launch** — the logged-in user does not hold `ALL` or `F_SYSTEM_SETTING`. Log in as a privileged user.
- **A check shows status `error`** — open the **Console** tab to inspect the raw API response. Network errors and unexpected payload shapes are surfaced here.
- **A settings check is reported as "not available on this DHIS2 version"** — the underlying setting key was introduced in a later DHIS2 release. Upgrade the server to enable that policy.
- **"Unable to verify default admin credentials"** — basic authentication may be disabled, or blocked by an SSO/proxy layer in front of DHIS2. The check reports a warning rather than a pass so the unverified state stays visible.
- **An app is reported as not scanned** — the request was answered by the login page or the app shell, or the entry HTML linked no scripts. Confirm the session is still valid and re-run.
- **"No app files could be hashed"** — the app is being served over plain HTTP, so Web Crypto is unavailable and integrity cannot be checked. Use HTTPS.
- **The browser tab freezes during the Apps Audit** — analysis runs on the main thread. Lower `maxAppAuditConcurrency` or `maxAppFileMb` in the **Configuration** tab.

## Reporting issues

File issues at [github.com/dhis2/security-auditor-app/issues](https://github.com/dhis2/security-auditor-app/issues). Include the DHIS2 version, the Security Auditor version (visible in the **System Info** tab), and where possible the contents of the **Console** tab for the failing check.

## Available Scripts

In the project directory, you can run:

### `yarn start`

Runs the app in the development mode.<br />
Open [http://localhost:3000](http://localhost:3000) to view it in the browser.

The page will reload if you make edits.<br />
You will also see any lint errors in the console.

### `yarn test`

Launches the test runner and runs all available tests found in `/src`.<br />

Run `yarn build` (or `yarn start`) at least once first: `src/App.jsx` imports `./locales`, which is gitignored and generated by `d2-app-scripts`, so on a fresh checkout the import cannot resolve until a build has run.

See the section about [running tests](https://platform.dhis2.nu/#/scripts/test) for more information.

### `yarn build`

Builds the app for production to the `build` folder.<br />
It correctly bundles React in production mode and optimizes the build for the best performance.

The build is minified and the filenames include the hashes.<br />
A deployable `.zip` file can be found in `build/bundle`!

`yarn build` and `yarn start` both run `scripts/sync-version.js` first, which regenerates `src/version.js` from `package.json` so the version shown in the **System Info** tab and the exported reports matches the released build. Don't edit that file by hand.

See the section about [building](https://platform.dhis2.nu/#/scripts/build) for more information.

### `yarn deploy`

Deploys the built app in the `build` folder to a running DHIS2 instance.<br />
This command will prompt you to enter a server URL as well as the username and password of a DHIS2 user with the App Management authority.<br/>
You must run `yarn build` before running `yarn deploy`.<br />

See the section about [deploying](https://platform.dhis2.nu/#/scripts/deploy) for more information.

## Continuous integration

- [`build.yml`](.github/workflows/build.yml) — builds and tests every push to `main` and every pull request, and uploads the bundle as an artifact.
- [`codeql.yml`](.github/workflows/codeql.yml) — CodeQL analysis with the `security-extended` query set, on push, PR and weekly.
- [`dependency-track.yml`](.github/workflows/dependency-track.yml) — generates a CycloneDX SBOM and uploads it to Dependency-Track. Requires the `DEPENDENCYTRACK_URL` repository variable and the `DEPENDENCYTRACK_APIKEY` secret.
- [`release.yml`](.github/workflows/release.yml) — the release pipeline described below.

## Releasing a New Version

Releases are created automatically when a PR is merged into `main` with a version label. Direct pushes to `main` do not trigger a release.

1. Create a branch and make your changes
   ```bash
   git checkout -b my-feature-branch
   # ... make changes ...
   git add src/
   git push -u origin my-feature-branch
   ```

2. Open a pull request against `main`
   ```bash
   gh pr create --title "My feature" --body ""
   ```

3. Add one of these labels to the PR:
   - `patch` — bug fixes, minor tweaks (e.g. `1.0.0` → `1.0.1`)
   - `minor` — new features, backwards-compatible (e.g. `1.0.0` → `1.1.0`)
   - `major` — breaking changes (e.g. `1.0.0` → `2.0.0`)
   ```bash
   gh pr edit --add-label minor
   ```

4. Merge the PR and delete the branch
   ```bash
   gh pr merge --merge --delete-branch
   ```

The CI pipeline will automatically:
- Bump the version in `package.json` and commit it to `main`
- Build the app and run the test suite (a failing test aborts the release)
- Tag the commit and create a GitHub Release with the `.zip` artifact attached

PRs carrying the `dependencies` label always release as a patch, whatever other version label Dependabot applied — a dependency's own major bump is not a breaking change to this app.

See [RELEASE.md](RELEASE.md) for the manual release path and for how to recover when you have already committed to local `main`.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
