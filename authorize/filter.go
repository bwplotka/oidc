package authorize

// Condition is just bool condition for whitelisting token perms.
type Condition func(tokenPerms []string) bool

// OR is an array of conditions with logic OR. If no condition is passed it returns false.
func OR(conditions ...Condition) Condition {
	return func(tokenPerms []string) bool {
		for _, condition := range conditions {
			if condition(tokenPerms) {
				return true
			}
		}
		return false
	}
}

// AND is an array of conditions with logic AND. If no condition is passed it returns false.
func AND(conditions ...Condition) Condition {
	return func(tokenPerms []string) bool {
		if len(conditions) == 0 {
			return false
		}

		for _, condition := range conditions {
			if !condition(tokenPerms) {
				return false
			}
		}
		return true
	}
}

// Contains is an condition that returns true token perms contains given permission.
func Contains(perms string) Condition {
	return func(tokenPerms []string) bool {
		for _, p := range tokenPerms {
			if p == perms {
				return true
			}
		}
		return false
	}
}
