// Parse a DHIS2 version string into { major, raw }.
//
// DHIS2 version strings have historically taken the form "2.42.0" (where the
// meaningful release number is the second component). Newer formats may drop
// the leading "2." entirely and use "42.0.0". The parser returns whichever
// component represents the major release.
export const parseDhis2Version = (versionStr) => {
    if (!versionStr) {
        return null
    }
    const parts = String(versionStr)
        .split('.')
        .map((p) => parseInt(p, 10))
        .filter((n) => Number.isFinite(n))
    if (parts.length === 0) {
        return null
    }
    // If the first component is small (legacy "2.X.Y" form), use the second.
    const major = parts[0] >= 10 ? parts[0] : parts[1] || 0
    return { major, raw: String(versionStr) }
}

// Field name for "password last updated" — flattened onto user in v42+,
// nested under user.userCredentials in earlier versions.
export const passwordLastUpdatedField = (version) =>
    version && version.major >= 42
        ? 'passwordLastUpdated'
        : 'userCredentials.passwordLastUpdated'
