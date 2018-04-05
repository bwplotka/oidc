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

	c, err := OR()
	assert.Error(t, err)

	c, err = OR(falseCond)
	assert.Error(t, err)

	c, err = OR(trueCond)
	assert.Error(t, err)

	c, err = OR(trueCond, trueCond, trueCond)
	assert.NoError(t, err)
	assert.True(t, c.isSatisfiedBy(somePerms), "true OR true OR true == true")
	assert.Equal(t, "(true || true || true)", c.stringRepr)

	c, err = OR(falseCond, falseCond, falseCond)
	assert.NoError(t, err)
	assert.False(t, c.isSatisfiedBy(somePerms), "false OR false OR false == false")
	assert.Equal(t, "(false || false || false)", c.stringRepr)

	c, err = OR(falseCond, trueCond, falseCond)
	assert.NoError(t, err)
	assert.True(t, c.isSatisfiedBy(somePerms), "false OR true OR false == true")
	assert.Equal(t, "(false || true || false)", c.stringRepr)
}

func TestAND(t *testing.T) {
	somePerms := []string{"a", "b", "c"}

	c, err := AND()
	assert.Error(t, err)

	c, err = AND(falseCond)
	assert.Error(t, err)

	c, err = AND(trueCond)
	assert.Error(t, err)

	c, err = AND(trueCond, trueCond, trueCond)
	assert.NoError(t, err)
	assert.True(t, c.isSatisfiedBy(somePerms), "true OR true OR true == true")
	assert.Equal(t, "(true && true && true)", c.stringRepr)

	c, err = AND(falseCond, falseCond, falseCond)
	assert.NoError(t, err)
	assert.False(t, c.isSatisfiedBy(somePerms), "false OR false OR false == false")
	assert.Equal(t, "(false && false && false)", c.stringRepr)

	c, err = AND(falseCond, trueCond, falseCond)
	assert.NoError(t, err)
	assert.False(t, c.isSatisfiedBy(somePerms), "false OR true OR false == false")
	assert.Equal(t, "(false && true && false)", c.stringRepr)
}

func TestComposite(t *testing.T) {
	orFF, err := OR(falseCond, falseCond)
	assert.NoError(t, err)

	andTT, err := AND(trueCond, trueCond)
	assert.NoError(t, err)

	orC, err := OR(falseCond, falseCond, trueCond, orFF, andTT)
	assert.NoError(t, err)

	assert.Equal(t, "(false || false || true || (false || false) || (true && true))", orC.stringRepr)
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
