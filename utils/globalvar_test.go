package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseIntEnvVar(t *testing.T) {
	tests := []struct {
		name         string
		varName      string
		varValue     string
		defaultValue int
		expected     int
		expectError  bool
	}{
		{
			name:         "environment variable not set",
			varName:      "TEST_ENV_VAR_NOT_SET",
			defaultValue: 10,
			expected:     10,
			expectError:  false,
		},
		{
			name:         "environment variable set with valid integer",
			varName:      "TEST_ENV_VAR_VALID",
			varValue:     "20",
			defaultValue: 10,
			expected:     20,
			expectError:  false,
		},
		{
			name:         "environment variable set with invalid integer",
			varName:      "TEST_ENV_VAR_INVALID",
			varValue:     "invalid",
			defaultValue: 10,
			expected:     10,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.varValue != "" {
				os.Setenv(tt.varName, tt.varValue)
			} else {
				os.Unsetenv(tt.varName)
			}

			val, err := parseIntEnvVar(tt.varName, tt.defaultValue)
			assert.Equalf(t, tt.expectError, err != nil, "unexpected error: %v", err)
			assert.Equalf(t, tt.expected, val, "unexpected value: %v", val)

		})
	}
}
