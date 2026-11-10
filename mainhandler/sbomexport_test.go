package mainhandler

import (
	"testing"
	"time"

	"github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func sbomExportConfig(t *testing.T, capabilities config.Capabilities, export config.SBOMExportConfig) config.IConfig {
	t.Helper()
	cfg, err := config.NewOperatorConfig(
		config.CapabilitiesConfig{Capabilities: capabilities},
		armometadata.ClusterConfig{ClusterName: "prod-cluster"},
		&beUtils.Credentials{},
		config.Config{SBOMExport: export},
	)
	require.NoError(t, err)
	return cfg
}

func TestNewSBOMExporter(t *testing.T) {
	valid := config.SBOMExportConfig{
		ResyncInterval:  time.Hour,
		DependencyTrack: config.DependencyTrackConfig{URL: "https://dtrack.example.com", APIKeyFile: "/etc/sbom-export/api-key"},
	}
	tt := []struct {
		name         string
		capabilities config.Capabilities
		export       config.SBOMExportConfig
		wantExporter bool
	}{
		{
			name:         "capability off",
			capabilities: config.Capabilities{NodeSbomGeneration: "enable"},
			export:       valid,
		},
		{
			name:         "without nodeSbomGeneration",
			capabilities: config.Capabilities{SBOMExport: "enable"},
			export:       valid,
		},
		{
			name:         "without a Dependency-Track URL",
			capabilities: config.Capabilities{SBOMExport: "enable", NodeSbomGeneration: "enable"},
			export:       config.SBOMExportConfig{ResyncInterval: time.Hour},
		},
		{
			name:         "capability on and configured",
			capabilities: config.Capabilities{SBOMExport: "enable", NodeSbomGeneration: "enable"},
			export:       valid,
			wantExporter: true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			mainHandler := &MainHandler{
				config:          sbomExportConfig(t, tc.capabilities, tc.export),
				k8sAPI:          utils.NewK8sInterfaceFake(k8sfake.NewClientset()),
				ksStorageClient: kssfake.NewClientset(),
			}
			assert.Equal(t, tc.wantExporter, mainHandler.newSBOMExporter() != nil)
		})
	}
}

func TestSBOMExportOptionsDefaultTheRootProjectToTheClusterName(t *testing.T) {
	export := config.SBOMExportConfig{
		ResyncInterval:  30 * time.Minute,
		DependencyTrack: config.DependencyTrackConfig{URL: "https://dtrack.example.com", APIKeyFile: "/keys/dtrack"},
	}
	opts := sbomExportOptions(sbomExportConfig(t, config.Capabilities{}, export))
	assert.Equal(t, "prod-cluster", opts.RootProject)
	assert.Equal(t, "https://dtrack.example.com", opts.URL)
	assert.Equal(t, "/keys/dtrack", opts.APIKeyFile)
	assert.Equal(t, 30*time.Minute, opts.ResyncInterval)

	export.DependencyTrack.RootProject = "prod"
	assert.Equal(t, "prod", sbomExportOptions(sbomExportConfig(t, config.Capabilities{}, export)).RootProject)
}
