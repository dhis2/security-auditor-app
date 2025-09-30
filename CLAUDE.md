# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a DHIS2 application built with the DHIS2 Application Platform. DHIS2 is a health information system platform, and this particular app is a security auditor tool for DHIS2 instances.

## Technology Stack

- **Framework**: React 18
- **Build System**: DHIS2 CLI App Scripts (`@dhis2/cli-app-scripts`)
- **Runtime**: DHIS2 App Runtime (`@dhis2/app-runtime`)
- **Internationalization**: DHIS2 i18n (`@dhis2/d2-i18n`)
- **Package Manager**: Yarn

## Development Commands

```bash
# Start development server (runs on http://localhost:3000)
yarn start

# Run tests
yarn test

# Build for production (output in build/ folder, deployable .zip in build/bundle/)
yarn build

# Deploy to DHIS2 instance (requires yarn build first)
yarn deploy
```

## Architecture

### Entry Point
- Main entry point: `src/App.jsx` (configured in `d2.config.js`)
- App uses DHIS2 App Runtime's `useDataQuery` hook for API interactions

### Configuration
- **d2.config.js**: DHIS2 app configuration
  - Type: `app`
  - Entry point: `./src/App.jsx`
  - Direction: `auto` (supports LTR/RTL)

### Data Fetching
All DHIS2 API interactions use the `@dhis2/app-runtime` hooks:
- `useDataQuery`: For fetching data from DHIS2 API
- Query format:
  ```javascript
  const query = {
    resourceName: {
      resource: 'api/endpoint',
    },
  }
  ```

### Internationalization
- Translation files: `i18n/en.pot` (source translations)
- Runtime locales: `src/locales/` (auto-generated during build/start)
- Use `i18n.t()` for all user-facing strings
- Example: `i18n.t('Hello {{name}}', { name: data.me.name })`

### Testing
- Tests located alongside source files (e.g., `App.test.jsx`)
- Use `CustomDataProvider` from `@dhis2/app-runtime` to wrap components in tests
- React 18 testing uses `createRoot` from `react-dom/client`

## DHIS2 Platform Resources

- [DHIS2 Application Platform Documentation](https://platform.dhis2.nu/)
- [DHIS2 Application Runtime Documentation](https://runtime.dhis2.nu/)