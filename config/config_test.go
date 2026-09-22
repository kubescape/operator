package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/operator/admission/rulesupdate"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRiskAcceptanceEnabled(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"enable", true},
		{"disable", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			cfg, err := NewOperatorConfig(
				CapabilitiesConfig{Capabilities: Capabilities{RiskAcceptance: tt.value}},
				armometadata.ClusterConfig{},
				&utils.Credentials{},
				Config{},
			)
			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.RiskAcceptanceEnabled())
		})
	}
}

func TestLoadConfigSkipProfilesOverride(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"skipProfilesWithoutInstances":false}`), 0600))
	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	assert.False(t, cfg.SkipProfilesWithoutInstances)
}

func TestLoadCapabilities(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    CapabilitiesConfig
		wantErr bool
	}{
		{
			name: "TestLoadCapabilities",
			args: args{
				path: "../configuration",
			},
			want: CapabilitiesConfig{
				Capabilities: Capabilities{
					ConfigurationScan:   "enable",
					ContinuousScan:      "disable",
					NodeScan:            "enable",
					Relevancy:           "enable",
					VulnerabilityScan:   "enable",
					AdmissionController: "enable",
				},
				Components: Components{
					HostScanner:        Component{Enabled: true},
					Kubescape:          Component{Enabled: true},
					KubescapeScheduler: Component{Enabled: true},
					Kubevuln:           Component{Enabled: true},
					KubevulnScheduler:  Component{Enabled: true},
					NodeAgent:          Component{Enabled: true},
					Operator:           Component{Enabled: true},
					OtelCollector:      Component{Enabled: true},
					ServiceDiscovery:   Component{Enabled: true},
					Storage:            Component{Enabled: true},
				},
				Configurations: Configurations{
					Persistence: "enable",
					Server: Server{
						DiscoveryURL: "foo.com",
					},
				},
				ServiceScanConfig: ServiceScanConfig{
					Interval: 60 * time.Second,
					Enabled:  true,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadCapabilitiesConfig(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadCapabilitiesConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadConfig(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    Config
		wantErr bool
	}{
		{
			name: "TestLoadConfig",
			args: args{
				path: "../configuration",
			},
			want: Config{
				Namespace:                    "kubescape",
				RestAPIPort:                  "4002",
				CleanUpRoutineInterval:       10 * time.Minute,
				ConcurrencyWorkers:           3,
				TriggerSecurityFramework:     false,
				MatchingRulesFilename:        "/etc/config/matchingRules.json",
				EventDeduplicationInterval:   2 * time.Minute,
				ExcludeNamespaces:            []string{"kube-system", "kubescape"},
				ExcludeNamespacesRegex:       []string{},
				IncludeNamespaces:            []string{},
				IncludeNamespacesRegex:       []string{},
				PodScanGuardTime:             time.Hour,
				SkipProfilesWithoutInstances: true,
				RulesUpdateConfig: rulesupdate.RulesUpdaterConfig{
					Enabled:   false,
					Interval:  5 * time.Minute,
					Namespace: "default",
				},
				NodeAgentAutoscaler: NodeAgentAutoscalerConfig{
					Enabled:          false,
					NodeGroupLabel:   "node.kubernetes.io/instance-type",
					DefaultNodeGroup: "default",
					ResourcePercentages: NodeAgentAutoscalerResourcePercentages{
						RequestCPU:    2,
						RequestMemory: 2,
						LimitCPU:      5,
						LimitMemory:   5,
					},
					MinResources: NodeAgentAutoscalerResourceBounds{
						CPU:    "100m",
						Memory: "180Mi",
					},
					MaxResources: NodeAgentAutoscalerResourceBounds{
						CPU:    "2000m",
						Memory: "4Gi",
					},
					ReconcileInterval:      5 * time.Minute,
					TemplatePath:           "/etc/templates/daemonset-template.yaml",
					OperatorDeploymentName: "operator",
					GoMemLimitPercentage:   0.8,
					SELinuxType:            "spc_t",
					BottlerocketAutoDetect: true,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadConfig(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateConfig(t *testing.T) {
	type args struct {
		clusterConfig armometadata.ClusterConfig
		components    CapabilitiesConfig
		credentials   *utils.Credentials
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "no clusterName: error",
			args: args{
				clusterConfig: armometadata.ClusterConfig{},
				components:    CapabilitiesConfig{},
				credentials:   &utils.Credentials{},
			},
			wantErr: true,
		},
		{
			name: "no discovery, no account: error",
			args: args{
				clusterConfig: armometadata.ClusterConfig{
					ClusterName: "foo",
				},
				components:  CapabilitiesConfig{},
				credentials: &utils.Credentials{},
			},
		},
		{
			name: "discovery, no account: error",
			args: args{
				clusterConfig: armometadata.ClusterConfig{
					ClusterName: "foo",
				},
				components: CapabilitiesConfig{
					Components: Components{ServiceDiscovery: Component{Enabled: true}},
				},
				credentials: &utils.Credentials{},
			},
			wantErr: true,
		},
		{
			name: "no discovery, account: no error",
			args: args{
				clusterConfig: armometadata.ClusterConfig{
					ClusterName: "foo",
				},
				credentials: &utils.Credentials{
					Account:   "123",
					AccessKey: "abc",
				},
				components: CapabilitiesConfig{},
			},
		},
		{
			name: "discovery, account: no error",
			args: args{
				clusterConfig: armometadata.ClusterConfig{
					ClusterName: "foo",
				},
				credentials: &utils.Credentials{
					Account:   "123",
					AccessKey: "abc",
				},
				components: CapabilitiesConfig{
					Components: Components{ServiceDiscovery: Component{Enabled: true}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			operatorConfig, err := NewOperatorConfig(tt.args.components, tt.args.clusterConfig, tt.args.credentials, Config{})
			require.NoError(t, err)
			err = ValidateConfig(operatorConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestDefaultFrameworks(t *testing.T) {
	tests := []struct {
		name       string
		frameworks []string
		want       []string
	}{
		{"empty", nil, nil},
		{"empty slice", []string{}, nil},
		{"blanks only", []string{"", "  "}, nil},
		{"custom", []string{"cis-aks-t1.2.0", "nsa"}, []string{"cis-aks-t1.2.0", "nsa"}},
		{"strips blanks", []string{"", "nsa", " "}, []string{"nsa"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewOperatorConfig(
				CapabilitiesConfig{},
				armometadata.ClusterConfig{InstallationData: armotypes.InstallationData{DefaultFrameworks: tt.frameworks}},
				&utils.Credentials{},
				Config{},
			)
			require.NoError(t, err)
			got := cfg.DefaultFrameworks()
			assert.Equal(t, tt.want, got)
			// returned slice must be a copy
			if len(got) > 0 {
				got[0] = "mutated"
				assert.Equal(t, tt.want, cfg.DefaultFrameworks())
			}
		})
	}
}

func TestLoadConfig_Regex(t *testing.T) {
	t.Run("valid comma string and json array", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()
		dir := t.TempDir()
		jsonContent := `{
			"includeNamespacesRegex": ["^team-[a,b]-.*$", "^prod-.*"],
			"excludeNamespacesRegex": "^temp-.*,^test-.*"
		}`
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(jsonContent), 0600))
		cfg, err := LoadConfig(dir)
		require.NoError(t, err)
		assert.Equal(t, []string{"^team-[a,b]-.*$", "^prod-.*"}, cfg.IncludeNamespacesRegex)
		assert.Equal(t, []string{"^temp-.*", "^test-.*"}, cfg.ExcludeNamespacesRegex)
	})

	t.Run("invalid include regex fails fast", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()
		dir := t.TempDir()
		jsonContent := `{"includeNamespacesRegex": "[a-"}`
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(jsonContent), 0600))
		_, err := LoadConfig(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid includeNamespacesRegex")
		assert.Contains(t, err.Error(), "invalid regex pattern \"[a-\"")
	})

	t.Run("invalid exclude regex fails fast", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()
		dir := t.TempDir()
		jsonContent := `{"excludeNamespacesRegex": "(?P<"}`
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(jsonContent), 0600))
		_, err := LoadConfig(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid excludeNamespacesRegex")
		assert.Contains(t, err.Error(), "invalid regex pattern \"(?P<\"")
	})
}

func TestOperatorConfig_SkipNamespace(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		namespace string
		wantSkip  bool
	}{
		{
			name:      "default config - nothing skipped",
			cfg:       Config{},
			namespace: "default",
			wantSkip:  false,
		},
		{
			name: "exact include - matching",
			cfg: Config{
				IncludeNamespaces: []string{"production"},
			},
			namespace: "production",
			wantSkip:  false,
		},
		{
			name: "exact include - not matching skipped",
			cfg: Config{
				IncludeNamespaces: []string{"production"},
			},
			namespace: "staging",
			wantSkip:  true,
		},
		{
			name: "regex include - matching",
			cfg: Config{
				IncludeNamespacesRegex: []string{"^team-.*-prod$"},
			},
			namespace: "team-auth-prod",
			wantSkip:  false,
		},
		{
			name: "regex include - not matching skipped",
			cfg: Config{
				IncludeNamespacesRegex: []string{"^team-.*-prod$"},
			},
			namespace: "team-auth-dev",
			wantSkip:  true,
		},
		{
			name: "mixed include - matches exact",
			cfg: Config{
				IncludeNamespaces:      []string{"kube-system"},
				IncludeNamespacesRegex: []string{"^team-.*-prod$"},
			},
			namespace: "kube-system",
			wantSkip:  false,
		},
		{
			name: "mixed include - matches regex",
			cfg: Config{
				IncludeNamespaces:      []string{"kube-system"},
				IncludeNamespacesRegex: []string{"^team-.*-prod$"},
			},
			namespace: "team-billing-prod",
			wantSkip:  false,
		},
		{
			name: "mixed include - matches neither skipped",
			cfg: Config{
				IncludeNamespaces:      []string{"kube-system"},
				IncludeNamespacesRegex: []string{"^team-.*-prod$"},
			},
			namespace: "team-billing-dev",
			wantSkip:  true,
		},
		{
			name: "exact exclude - matching skipped",
			cfg: Config{
				ExcludeNamespaces: []string{"kube-system"},
			},
			namespace: "kube-system",
			wantSkip:  true,
		},
		{
			name: "exact exclude - not matching allowed",
			cfg: Config{
				ExcludeNamespaces: []string{"kube-system"},
			},
			namespace: "default",
			wantSkip:  false,
		},
		{
			name: "regex exclude - matching skipped",
			cfg: Config{
				ExcludeNamespacesRegex: []string{"^dev-.*", "^temp-.*"},
			},
			namespace: "dev-feature-1",
			wantSkip:  true,
		},
		{
			name: "regex exclude - not matching allowed",
			cfg: Config{
				ExcludeNamespacesRegex: []string{"^dev-.*", "^temp-.*"},
			},
			namespace: "prod-service",
			wantSkip:  false,
		},
		{
			name: "mixed exclude - matches exact skipped",
			cfg: Config{
				ExcludeNamespaces:      []string{"kube-system"},
				ExcludeNamespacesRegex: []string{"^temp-.*"},
			},
			namespace: "kube-system",
			wantSkip:  true,
		},
		{
			name: "mixed exclude - matches regex skipped",
			cfg: Config{
				ExcludeNamespaces:      []string{"kube-system"},
				ExcludeNamespacesRegex: []string{"^temp-.*"},
			},
			namespace: "temp-sandbox",
			wantSkip:  true,
		},
		{
			name: "mixed exclude - matches neither allowed",
			cfg: Config{
				ExcludeNamespaces:      []string{"kube-system"},
				ExcludeNamespacesRegex: []string{"^temp-.*"},
			},
			namespace: "default",
			wantSkip:  false,
		},
		{
			name: "include precedence over exclude - matching include is allowed even if in exclude",
			cfg: Config{
				IncludeNamespaces: []string{"payments"},
				ExcludeNamespaces: []string{"payments", "kube-system"},
			},
			namespace: "payments",
			wantSkip:  false,
		},
		{
			name: "include precedence over exclude - non-matching include is skipped",
			cfg: Config{
				IncludeNamespaces:      []string{"payments"},
				ExcludeNamespaces:      []string{"kube-system"},
				ExcludeNamespacesRegex: []string{".*"},
			},
			namespace: "default",
			wantSkip:  true,
		},
		{
			name: "include regex precedence over exclude regex",
			cfg: Config{
				IncludeNamespacesRegex: []string{"^team-.*"},
				ExcludeNamespacesRegex: []string{"^team-.*-staging$"},
			},
			namespace: "team-auth-staging",
			wantSkip:  false,
		},
		{
			name: "unanchored regex matches substring anywhere",
			cfg: Config{
				ExcludeNamespacesRegex: []string{"team-"},
			},
			namespace: "my-team-staging",
			wantSkip:  true,
		},
		{
			name: "anchored regex does not match substring",
			cfg: Config{
				ExcludeNamespacesRegex: []string{"^team-.*$"},
			},
			namespace: "my-team-staging",
			wantSkip:  false,
		},
		{
			name: "empty and whitespace regex patterns are ignored",
			cfg: Config{
				IncludeNamespacesRegex: []string{"", "  ", "\t"},
			},
			namespace: "default",
			wantSkip:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opCfg, err := NewOperatorConfig(
				CapabilitiesConfig{},
				armometadata.ClusterConfig{},
				&utils.Credentials{},
				tt.cfg,
			)
			require.NoError(t, err)
			got := opCfg.SkipNamespace(tt.namespace)
			assert.Equal(t, tt.wantSkip, got)
		})
	}
}

func TestOperatorConfig_Getters(t *testing.T) {
	cfg := Config{
		IncludeNamespaces:      []string{"inc1"},
		ExcludeNamespaces:      []string{"exc1"},
		IncludeNamespacesRegex: []string{"^inc-.*$"},
		ExcludeNamespacesRegex: []string{"^exc-.*$"},
	}
	opCfg, err := NewOperatorConfig(
		CapabilitiesConfig{},
		armometadata.ClusterConfig{},
		&utils.Credentials{},
		cfg,
	)
	require.NoError(t, err)

	assert.Equal(t, []string{"inc1"}, opCfg.IncludeNamespaces())
	assert.Equal(t, []string{"exc1"}, opCfg.ExcludeNamespaces())
	assert.Equal(t, []string{"^inc-.*$"}, opCfg.IncludeNamespacesRegex())
	assert.Equal(t, []string{"^exc-.*$"}, opCfg.ExcludeNamespacesRegex())
}

func TestNewOperatorConfig_RegexValidation(t *testing.T) {
	t.Run("valid include and exclude regexes succeed", func(t *testing.T) {
		cfg := Config{
			IncludeNamespacesRegex: []string{"^team-[a,b]-.*$", "^prod-.*"},
			ExcludeNamespacesRegex: []string{"^temp-.*", "^test-.*"},
		}
		opCfg, err := NewOperatorConfig(CapabilitiesConfig{}, armometadata.ClusterConfig{}, &utils.Credentials{}, cfg)
		require.NoError(t, err)
		require.NotNil(t, opCfg)
		assert.Equal(t, []string{"^team-[a,b]-.*$", "^prod-.*"}, opCfg.IncludeNamespacesRegex())
		assert.Equal(t, []string{"^temp-.*", "^test-.*"}, opCfg.ExcludeNamespacesRegex())
	})

	t.Run("mixed valid and invalid include regex fails fast", func(t *testing.T) {
		cfg := Config{
			IncludeNamespacesRegex: []string{"^prod$", "["},
		}
		opCfg, err := NewOperatorConfig(CapabilitiesConfig{}, armometadata.ClusterConfig{}, &utils.Credentials{}, cfg)
		require.Error(t, err)
		assert.Nil(t, opCfg)
		assert.Contains(t, err.Error(), "invalid includeNamespacesRegex")
		assert.Contains(t, err.Error(), "invalid regex pattern \"[\"")
	})

	t.Run("mixed valid and invalid exclude regex fails fast", func(t *testing.T) {
		cfg := Config{
			ExcludeNamespacesRegex: []string{"^dev-.*", "(?P<"},
		}
		opCfg, err := NewOperatorConfig(CapabilitiesConfig{}, armometadata.ClusterConfig{}, &utils.Credentials{}, cfg)
		require.Error(t, err)
		assert.Nil(t, opCfg)
		assert.Contains(t, err.Error(), "invalid excludeNamespacesRegex")
		assert.Contains(t, err.Error(), "invalid regex pattern \"(?P<\"")
	})

	t.Run("empty and whitespace regexes succeed and are ignored", func(t *testing.T) {
		cfg := Config{
			IncludeNamespacesRegex: []string{"", "  ", "\t"},
			ExcludeNamespacesRegex: []string{" ", ""},
		}
		opCfg, err := NewOperatorConfig(CapabilitiesConfig{}, armometadata.ClusterConfig{}, &utils.Credentials{}, cfg)
		require.NoError(t, err)
		require.NotNil(t, opCfg)
		assert.False(t, opCfg.SkipNamespace("default"))
	})
}
