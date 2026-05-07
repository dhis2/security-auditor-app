// Bounds for each numeric config field. The same constraints are applied
// when saving from the UI (handles NaN from cleared inputs) and when
// importing a JSON config file.
const RULES = {
    minPasswordLength: { label: 'Minimum password length', min: 1, max: 128 },
    maxInactiveMonths: { label: 'Maximum inactive months', min: 1, max: 120 },
    maxPasswordAgeDays: { label: 'Maximum password age (days)', min: 1, max: 3650 },
    maxSuperUserRoles: { label: 'Maximum super user roles', min: 1, max: 1000 },
}

export const REQUIRED_CONFIG_KEYS = Object.keys(RULES)

// Validate a config object. Returns an array of human-readable error messages;
// an empty array means the config is valid.
export const validateConfig = (config) => {
    const errors = []
    if (!config || typeof config !== 'object') {
        return ['Configuration must be an object']
    }
    for (const key of REQUIRED_CONFIG_KEYS) {
        const rule = RULES[key]
        const value = config[key]
        if (typeof value !== 'number' || !Number.isFinite(value)) {
            errors.push(`${rule.label} must be a number`)
            continue
        }
        if (!Number.isInteger(value)) {
            errors.push(`${rule.label} must be a whole number`)
            continue
        }
        if (value < rule.min || value > rule.max) {
            errors.push(
                `${rule.label} must be between ${rule.min} and ${rule.max}`
            )
        }
    }
    return errors
}
