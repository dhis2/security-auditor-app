This project was bootstrapped with [DHIS2 Application Platform](https://github.com/dhis2/app-platform).

## Overview

The Security Auditor is a DHIS2 application that performs read-only security checks against your DHIS2 instance and reports findings. It is intended for system administrators and security reviewers and helps surface common misconfigurations: weak password policies, over-privileged user roles, missing security headers, unsafe CORS configuration, dormant accounts, and similar issues.

The audit runs entirely client-side — no data leaves your DHIS2 instance. All checks use the standard DHIS2 Web API via the authenticated session of the currently logged-in user.

## Requirements

- DHIS2 server **v39 or later**. The app has been tested on v39, v40, v41 and v42.
- The user running the audit must hold the `ALL` authority **or** the `F_SYSTEM_SETTING` authority.
- A modern browser (Chrome/Firefox/Edge/Safari, current versions).

A handful of checks rely on settings that are only present on newer DHIS2 versions (e.g. `enforceVerifiedEmail` was introduced in v42). On older instances those checks report as a warning labelled "not available on this DHIS2 version" rather than as an error.

## Installation

### From the App Hub
1. In DHIS2, go to **App Management**.
2. Search for **Security Auditor** and click **Install**.
3. Open the app from the app menu.

### From source
```bash
yarn install
yarn build
yarn deploy   # prompts for server URL and admin credentials
```
The `yarn deploy` command requires a DHIS2 user with the **App Management** authority.

## Usage

1. Open the **Security Auditor** app from the DHIS2 app menu.
2. (Optional) Open the **Configuration** tab to adjust thresholds. See [Configuration](#configuration) below.
3. Click **Start Audit**. Each check runs in sequence; the **Audit Results** tab updates as findings come in.
4. Review findings, sorted by severity (failures first, then warnings, then passes).
5. Click **Export Report** in the **Audit Results** tab to download a self-contained HTML report you can share with stakeholders.
6. The **System Info** tab shows the DHIS2 version, server URL, system ID and the Security Auditor version that produced the report.
7. The **Console** tab shows the raw API responses for each check, useful for debugging or producing evidence.

## Configuration

Thresholds are stored per-instance in the DHIS2 dataStore (namespace `security-auditor-app`). Defaults:

| Setting              | Default   | Used by                                                  |
| -------------------- | --------- | -------------------------------------------------------- |
| `minPasswordLength`  | 8         | Password Policy Configuration                            |
| `maxInactiveMonths`  | 3 months  | Inactive User Accounts                                   |
| `maxPasswordAgeDays` | 365 days  | Password Age Verification                                |
| `maxSuperUserRoles`  | 5         | Threshold for "too many users with privileged authority" |

Edit values in the **Configuration** tab and click **Save**. Changes apply on the next audit run.

## Checks performed

User & role checks:
- **Users With ALL Authority** — flags if too many users hold the unrestricted `ALL` authority.
- **Users Who Can Manage Routes** — flags users with the route-management authority.
- **Users Who Can Impersonate Others** — flags users with `F_IMPERSONATE_USER`.
- **Users Who Can Change System Settings** — flags users with `F_SYSTEM_SETTING`.
- **Users Never Logged In** — surfaces active accounts that have never been used.
- **Inactive User Accounts** — surfaces active accounts inactive longer than the configured threshold.
- **Password Age Verification** — flags users whose passwords exceed the configured maximum age.
- **Default Admin Password Check** — flags the `admin` account if its password has not been changed since the account was created.

Server policy checks:
- **Password Policy Configuration** — verifies `minPasswordLength` meets the configured minimum.
- **Password Expiry Policy** — flags if `credentialsExpires` is disabled.
- **Email Verification Enforcement** — flags if `enforceVerifiedEmail` is not `true` (DHIS2 v42+).
- **Account Lockout Policy** — flags if `lockMultipleFailedLogins` is not enabled.
- **CORS Whitelist Configuration** — flags wildcards or a populated whitelist on `configuration/corsWhitelist`.

Transport & header checks (issued against the DHIS2 server):
- **HTTPS Connection Security** — fails if the app is served over plain HTTP.
- **HTTP Strict Transport Security (HSTS)** — checks the `Strict-Transport-Security` response header.
- **Server Header Exposure** — flags if the server discloses its identity via the `Server` header.
- **Cross-Origin Opener Policy (COOP)** — checks the `Cross-Origin-Opener-Policy` header.
- **Cross-Origin Embedder Policy (COEP)** — checks the `Cross-Origin-Embedder-Policy` header.
- **Cross-Origin Resource Policy (CORP)** — checks the `Cross-Origin-Resource-Policy` header.
- **CORS Headers Configuration** — flags unsafe `Access-Control-Allow-Origin` values.
- **Content Security Policy (CSP)** — checks for a present, sane `Content-Security-Policy` header.

## Troubleshooting

- **"Administrator Access Required" on launch** — the logged-in user does not hold `ALL` or `F_SYSTEM_SETTING`. Log in as a privileged user.
- **A check shows status `error`** — open the **Console** tab to inspect the raw API response. Network errors and unexpected payload shapes are surfaced here.
- **A settings check is reported as "not available on this DHIS2 version"** — the underlying setting key was introduced in a later DHIS2 release. Upgrade the server to enable that policy.

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

See the section about [running tests](https://platform.dhis2.nu/#/scripts/test) for more information.

### `yarn build`

Builds the app for production to the `build` folder.<br />
It correctly bundles React in production mode and optimizes the build for the best performance.

The build is minified and the filenames include the hashes.<br />
A deployable `.zip` file can be found in `build/bundle`!

See the section about [building](https://platform.dhis2.nu/#/scripts/build) for more information.

### `yarn deploy`

Deploys the built app in the `build` folder to a running DHIS2 instance.<br />
This command will prompt you to enter a server URL as well as the username and password of a DHIS2 user with the App Management authority.<br/>
You must run `yarn build` before running `yarn deploy`.<br />

See the section about [deploying](https://platform.dhis2.nu/#/scripts/deploy) for more information.

## Releasing a New Version

Releases are created automatically when a PR is merged into `main` with a version label.

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
- Build the app
- Create a GitHub Release with the `.zip` artifact attached
