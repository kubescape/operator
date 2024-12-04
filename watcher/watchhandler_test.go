package watcher

import (
	_ "embed"
	"testing"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestNewWatchHandlerProducesValidResult(t *testing.T) {
	tt := []struct {
		imageIDsToWLIDSsMap map[string][]string
		expectedIWMap       map[string][]string
		name                string
	}{
		{
			name:                "Creating with provided empty map returns matching empty map",
			imageIDsToWLIDSsMap: map[string][]string{},
			expectedIWMap:       map[string][]string{},
		},
		{
			name:                "Creating with provided nil map returns matching empty map",
			imageIDsToWLIDSsMap: nil,
			expectedIWMap:       map[string][]string{},
		},
		{
			name: "Creating with provided non-empty map returns matching map",
			imageIDsToWLIDSsMap: map[string][]string{
				"imageid-01": {"wlid-01"},
			},
			expectedIWMap: map[string][]string{
				"imageid-01": {"wlid-01"},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			clusterConfig := utilsmetadata.ClusterConfig{}
			cfg, err := config.LoadConfig("../configuration")
			assert.NoError(t, err)
			operatorConfig := config.NewOperatorConfig(config.CapabilitiesConfig{}, clusterConfig, &beUtils.Credentials{}, "", cfg)

			k8sClient := k8sfake.NewSimpleClientset()
			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			storageClient := kssfake.NewSimpleClientset()

			wh := NewWatchHandler(operatorConfig, k8sAPI, storageClient, nil)

			assert.NotNilf(t, wh, "Constructing should create a non-nil object")
		})
	}
}
