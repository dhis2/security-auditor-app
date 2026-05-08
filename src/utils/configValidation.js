// Bounds for each numeric config field. The same constraints are applied
// when saving from the UI (handles NaN from cleared inputs) and when
// importing a JSON config file. These bounds must match the `min`/`max`
// attributes on the corresponding InputField in ConfigurationPanel.jsx.
const RULES = {
    minPasswordLength: { label: 'Minimum password length', min: 1, max: 50 },
    maxInactiveMonths: { label: 'Maximum inactive months', min: 1, max: 24 },
    maxPasswordAgeDays: { label: 'Maximum password age (days)', min: 30, max: 1095 },
    maxSuperUserRoles: {
        label: 'Maximum users with privileged authorities',
        min: 1,
        max: 50,
    },
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
