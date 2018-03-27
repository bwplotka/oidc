package authorize

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	trueCond = Condition{
		stringRepr:    "true",
		isSatisfiedBy: func([]string) bool { return true },
	}
	falseCond = Condition{
		stringRepr:    "false",
		isSatisfiedBy: func([]string) bool { return false },
	}
)

func TestOR(t *testing.T) {
	somePerms := []string{"a", "b", "c"}

	c := OR()
	assert.False(t, c.isSatisfiedBy(somePerms), "empty OR should return false.")
	assert.Equal(t, "( || )", c.stringRepr)

	c = OR(falseCond)
	assert.False(t, c.isSatisfiedBy(somePerms), "false == false")
	assert.Equal(t, "(false)", c.stringRepr)

	c = OR(trueCond)
	assert.True(t, c.isSatisfiedBy(somePerms), "true == true")
	assert.Equal(t, "(true)", c.stringRepr)

	c = OR(trueCond, trueCond, trueCond)
	assert.True(t, c.isSatisfiedBy(somePerms), "true OR true OR true == true")
	assert.Equal(t, "(true || true || true)", c.stringRepr)

	c = OR(falseCond, falseCond, falseCond)
	assert.False(t, c.isSatisfiedBy(somePerms), "false OR false OR false == false")
	assert.Equal(t, "(false || false || false)", c.stringRepr)

	c = OR(falseCond, trueCond, falseCond)
	assert.True(t, c.isSatisfiedBy(somePerms), "false OR true OR false == true")
	assert.Equal(t, "(false || true || false)", c.stringRepr)
}

func TestAND(t *testing.T) {
	somePerms := []string{"a", "b", "c"}

	c := AND()
	assert.False(t, c.isSatisfiedBy(somePerms), "empty AND should return false.")
	assert.Equal(t, "( && )", c.stringRepr)

	c = AND(falseCond)
	assert.False(t, c.isSatisfiedBy(somePerms), "false == false")
	assert.Equal(t, "(false)", c.stringRepr)

	c = AND(trueCond)
	assert.True(t, c.isSatisfiedBy(somePerms), "true == true")
	assert.Equal(t, "(true)", c.stringRepr)

	c = AND(trueCond, trueCond, trueCond)
	assert.True(t, c.isSatisfiedBy(somePerms), "true OR true OR true == true")
	assert.Equal(t, "(true && true && true)", c.stringRepr)

	c = AND(falseCond, falseCond, falseCond)
	assert.False(t, c.isSatisfiedBy(somePerms), "false OR false OR false == false")
	assert.Equal(t, "(false && false && false)", c.stringRepr)

	c = AND(falseCond, trueCond, falseCond)
	assert.False(t, AND(falseCond, trueCond, falseCond).isSatisfiedBy(somePerms), "false OR true OR false == false")
	assert.Equal(t, "(false && true && false)", c.stringRepr)
}

func TestComposite(t *testing.T) {
	assert.Equal(t, "(false || false || true || (false) || (true && true))", OR(falseCond, falseCond, trueCond, OR(falseCond), AND(trueCond, trueCond)).stringRepr)
}

func TestContains(t *testing.T) {
	cond := Contains("a")
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
		assert.Equal(t, spec.expected, cond.isSatisfiedBy(spec.perms), fmt.Sprintf("Should work for %v", spec.perms))
	}
}
