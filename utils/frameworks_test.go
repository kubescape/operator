package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFrameworksOrDefault(t *testing.T) {
	assert.Equal(t, []string{"nsa"}, FrameworksOrDefault([]string{"nsa"}, NativeDefaultFrameworks))
	assert.Equal(t, NativeDefaultFrameworks, FrameworksOrDefault(nil, NativeDefaultFrameworks))
	assert.Equal(t, NativeDefaultFrameworks, FrameworksOrDefault([]string{}, NativeDefaultFrameworks))

	got := FrameworksOrDefault([]string{"nsa"}, NativeDefaultFrameworks)
	got[0] = "mutated"
	assert.Equal(t, []string{"nsa"}, FrameworksOrDefault([]string{"nsa"}, NativeDefaultFrameworks))
}
