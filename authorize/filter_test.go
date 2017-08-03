package authorize_test

import (
	"fmt"
	"testing"

	"github.com/Bplotka/oidc/authorize"
	"github.com/stretchr/testify/assert"
)

var (
	trueCond  = func([]string) bool { return true }
	falseCond = func([]string) bool { return false }
)

func TestOR(t *testing.T) {
	somePerms := []string{"a", "b", "c"}

	assert.False(t, authorize.OR()(somePerms), "empty OR should return false.")

	assert.False(t, authorize.OR(falseCond)(somePerms), "false == false")
	assert.True(t, authorize.OR(trueCond)(somePerms), "true == true")

	assert.True(t, authorize.OR(trueCond, trueCond, trueCond)(somePerms), "true OR true OR true == true")
	assert.False(t, authorize.OR(falseCond, falseCond, falseCond)(somePerms), "false OR false OR false == false")
	assert.True(t, authorize.OR(falseCond, trueCond, falseCond)(somePerms), "false OR true OR false == true")
}

func TestAND(t *testing.T) {
	somePerms := []string{"a", "b", "c"}

	assert.False(t, authorize.AND()(somePerms), "empty AND should return false.")

	assert.False(t, authorize.AND(falseCond)(somePerms), "false == false")
	assert.True(t, authorize.AND(trueCond)(somePerms), "true == true")

	assert.True(t, authorize.AND(trueCond, trueCond, trueCond)(somePerms), "true OR true OR true == true")
	assert.False(t, authorize.AND(falseCond, falseCond, falseCond)(somePerms), "false OR false OR false == false")
	assert.False(t, authorize.AND(falseCond, trueCond, falseCond)(somePerms), "false OR true OR false == false")
}

func TestContains(t *testing.T) {
	cond := authorize.Contains("a")
	for _, spec := range []struct {
		perms    []string
		expected bool
	}{
		{
			perms:    []string{},
			expected: false,
		},
		{
			perms:    []string{"a"},
			expected: true,
		},
		{
			perms:    []string{"b", "c"},
			expected: false,
		},
		{
			perms:    []string{"a", "a", "a"},
			expected: true,
		},
	} {
		assert.Equal(t, spec.expected, cond(spec.perms), fmt.Sprintf("Should work for %v", spec.perms))
	}
}
