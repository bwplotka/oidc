package authorize

import (
	"fmt"
	"strings"
)

// Condition is used to check whether user with tokenPerms has access.
type Condition struct {
	isSatisfiedBy func(tokenPerms []string) bool
	stringRepr    string
}

// OR is an array of conditions with logic OR. If no condition is passed it returns false.
func OR(conditions ...Condition) (Condition, error) {
	if len(conditions) < 2 {
		return Condition{}, fmt.Errorf("OR condition must be used for 2 or more elements, got: %v", conditions)
	}
	return Condition{
		isSatisfiedBy: func(tokenPerms []string) bool {
			for _, condition := range conditions {
				if condition.isSatisfiedBy(tokenPerms) {
					return true
				}
			}
			return false
		},
		stringRepr: mkStringRepr(conditions, " || "),
	}, nil
}

// AND is an array of conditions with logic AND. If no condition is passed it returns false.
func AND(conditions ...Condition) (Condition, error) {
	if len(conditions) < 2 {
		return Condition{}, fmt.Errorf("OR condition must be used for 2 or more elements, got: %v", conditions)
	}
	return Condition{
		isSatisfiedBy: func(tokenPerms []string) bool {
			for _, condition := range conditions {
				if !condition.isSatisfiedBy(tokenPerms) {
					return false
				}
			}
			return true
		},
		stringRepr: mkStringRepr(conditions, " && "),
	}, nil
}

// Contains is an condition that returns true token perms contains given permission.
func Contains(perm string) Condition {
	return Condition{
		isSatisfiedBy: func(tokenPerms []string) bool {
			for _, p := range tokenPerms {
				if p == perm {
					return true
				}
			}
			return false
		},
		stringRepr: perm,
	}
}

// mkStringRepr will return string representation of conditions created by combining other conditions by operator.
func mkStringRepr(conditions []Condition, operator string) string {
	reprs := make([]string, len(conditions))
	for i, cond := range conditions {
		reprs[i] = cond.stringRepr
	}
	return fmt.Sprintf("(%s)", strings.Join(reprs, operator))
}
