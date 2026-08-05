# Known Issues

Problems that are understood but not fixed, with enough detail to pick the work
up later. Fixed issues are removed from this file.

## Strings are silently dropped from `i18n/en.pot` during extraction

**Status:** open · **Affects:** every localized build · **Found:** 2026-08-05

### Summary

62 of the app's ~420 translatable strings never reach `i18n/en.pot`, and one
more is written to it truncated. They are correctly wrapped in `i18n.t()`, they
render correctly in English, and nothing in the build fails — but they are never
offered to translators, so they can only ever appear in English. The app is
therefore about 85% localizable, not 100%, and the gap is invisible from the
source.

The cause is in the platform tooling, not in this repo:
`@dhis2/cli-app-scripts` builds its `i18next-scanner` parser with
`keySeparator: false` but leaves i18next's other key-parsing defaults active
([`src/lib/i18n/extract.js`](https://github.com/dhis2/app-platform/blob/master/cli/src/lib/i18n/extract.js), around line 29):

```js
var parser = new scanner.Parser({
    keepRemoved: false,
    keySeparator: false,     // disabled
    sort: true,              // nsSeparator (':') left at its default
    defaultValue: (lng, ns, key, options) => ...
})
```

Verified against `@dhis2/cli-app-scripts` 12.11.3 / `i18next-scanner` 3.3.0.

### Three symptoms

**1. Any message containing a colon is dropped (59 strings).**
`nsSeparator` defaults to `':'`, so `i18n.t('Error: {{message}}')` is parsed as
namespace `Error` + key `' {{message}}'`, which belongs to no namespace and is
discarded. Messages with a colon *inside* the sentence log a warning during
extraction; messages that merely *end* with a colon are dropped with no output
at all.

**2. Any message passing a `count` option is dropped (3 strings).**
i18next treats `count` as the plural selector. The parser routes these into
plural handling and emits nothing — `i18n/en.pot` contains zero `msgid_plural`
entries and zero occurrences of `{{count}}`.

**3. One message is written truncated (1 string).**
`Threshold for the number of users holding privileged authorities (ALL,
F_PUBLIC_ROUTE_ADD, F_IMPERSONATE_USER, or F_SYSTEM_SETTING) before a warning is
raised` appears in the POT cut off at `…or F_SYSTEM`, while its `msgstr` holds
the full text. This one happens downstream, in the JSON→PO step
(`i18next-conv`, which splits keys on `_` for plural and context suffixes).
Truncation is worse than dropping: a translator sees a broken sentence and
translates it, and the result never matches the runtime lookup key.

Runtime is unaffected in English. `@dhis2/d2-i18n` sets `nsSeparator: false`, so
`i18n.t('Error: {{message}}')` renders as expected and falls back to the key
when no translation exists. Only extraction is broken.

### Reproducing

```bash
yarn d2-app-scripts i18n extract
# i18next-scanner: "Error" does not exist in the namespaces (["translation"]): key=" {{message}}"

grep -c 'msgid ".*: ' i18n/en.pot   # 0 — no colon-bearing message was extracted
grep -c '{{count}}'   i18n/en.pot   # 0 — no count-bearing message was extracted
grep -c 'msgid_plural' i18n/en.pot  # 0
```

Minimal proof against the scanner directly, using the platform's parser options:

```js
const scanner = require('i18next-scanner')
const parser = new scanner.Parser({ keepRemoved: false, keySeparator: false, sort: true,
    defaultValue: (l, n, k, o) => (o.defaultValue ? o.defaultValue : k) })
parser.parseFuncFromString(`
    i18n.t('Plain string')
    i18n.t('Has a colon: {{message}}', { message: m })
    i18n.t('Count {{count}} things', { count: n })
    i18n.t('Trailing colon:')
`).get()
console.log(parser.get().en.translation)
// => { 'Plain string': 'Plain string' }   — the other three are gone
```

### Affected strings

Colon-bearing call sites, by file (59 distinct strings, 66 call sites):

| File | Sites |
| --- | --- |
| `src/audit/checks/headers.js` | 27 |
| `src/components/AppsAudit.jsx` | 16 |
| `src/audit/checks/users.js` | 6 |
| `src/components/AuditFindings.jsx` | 5 |
| `src/audit/apps/scanApp.js` | 3 |
| `src/audit/checks/settings.js` | 3 |
| `src/audit/helpers.js` | 3 |
| `src/audit/apps/appsBaseline.js` | 1 |
| `src/audit/checks/connection.js` | 1 |
| `src/hooks/useSecurityAudit.js` | 1 |

This covers all of the HSTS/COOP/COEP/CORP/CORS/CSP header findings, the
user-sample messages (`Consider removing unused accounts: {{sample}}`), every
`Error: {{message}}`, and all the exported-report summary labels
(`Report Generated:`, `Total Apps:`, `Failed:`, …).

The three `count` strings are in `src/audit/apps/scanApp.js`,
`src/audit/checks/appSources.js` and `src/audit/checks/connection.js`. The
truncated string is the `Maximum Privileged Users` help text in
`src/components/ConfigurationPanel.jsx`.

Recount after any change:

```bash
python3 - <<'EOF'
import re, pathlib
pat = re.compile(r"i18n\.t\(\s*(['\"])((?:\\.|(?!\1).)*)\1", re.S)
hits = [(p, m.group(2)) for p in pathlib.Path('src').rglob('*')
        if p.suffix in ('.js', '.jsx') and '.test.' not in p.name
        for m in pat.finditer(p.read_text()) if ':' in m.group(2)]
print(len({s for _, s in hits}), 'distinct,', len(hits), 'call sites')
EOF
```

### Recommended fix

Fix it upstream in `@dhis2/app-platform`, rather than working around it here.
The scanner is constructed once, in one file, and the fix is to pin the key
parsing off entirely:

```js
var parser = new scanner.Parser({
    keepRemoved: false,
    keySeparator: false,
    nsSeparator: false,      // add
    contextSeparator: false, // add — also covers the i18next-conv truncation
    plural: false,           // add — or keep plurals and emit msgid_plural properly
    sort: true,
    defaultValue: (lng, ns, key, options) => ...
})
```

This matches what `@dhis2/d2-i18n` already does at runtime (`nsSeparator:
false`), so extraction and lookup would finally agree on what a key is. It fixes
every DHIS2 app at once — the bug is not specific to this one, and any app whose
messages contain a colon has the same silent hole.

Steps:

1. File an issue against [dhis2/app-platform](https://github.com/dhis2/app-platform/issues)
   with the minimal repro above.
2. Open a PR against `cli/src/lib/i18n/extract.js` adding the options, plus a
   scanner test covering a colon message, a trailing-colon message, and a
   `count` message.
3. Once released, bump `@dhis2/cli-app-scripts` here, re-run
   `yarn d2-app-scripts i18n extract`, and commit the ~62 recovered strings.

**Interim option, if translations are needed before that lands:** pass
`nsSeparator: false` in the options object at each affected call site. The
scanner honours a per-call override, and it is a no-op at runtime. It works
today but costs ~66 mechanical edits, roughly 20 of which currently have no
options argument at all, and it does not help the `count` or truncation cases.

**Do not** fix this by rewording messages to avoid colons. It reads as
arbitrary, it does not survive the next contributor writing a normal sentence,
and it leaves the underlying tooling bug in place for everyone else.
