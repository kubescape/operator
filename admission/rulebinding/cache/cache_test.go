package cache

import (
	"testing"

	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/assert"
)

func TestNewCache(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "Initialize NewCache",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sAPI := utils.NewK8sInterfaceFake(nil)
			cache := NewCache(k8sAPI)

			assert.NotNil(t, cache)
			assert.Equal(t, k8sAPI, cache.k8sClient)
			assert.NotNil(t, cache.ruleCreator)
			assert.NotNil(t, cache.watchResources)
		})
	}
}
