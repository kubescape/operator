package cache

import (
	"testing"

	typesv1 "node-agent/pkg/rulebindingmanager/types/v1"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestResourcesToWatch(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "Test with valid resources",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resourcesToWatch()

			assert.Equal(t, 1, len(result))

			rbResource := result[0]
			assert.Equal(t, typesv1.RuleBindingAlertGvr, rbResource.GroupVersionResource())
			assert.Equal(t, metav1.ListOptions{}, rbResource.ListOptions())
		})
	}
}
