package config

import (
	"testing"
	"time"

	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/stretchr/testify/assert"
)

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
					ConfigurationScan:    "enable",
					ContinuousScan:       "disable",
					NetworkGenerator:     "disable",
					NodeScan:             "enable",
					Otel:                 "enable",
					Relevancy:            "enable",
					RuntimeObservability: "disable",
					Seccomp:              "disable",
					VulnerabilityScan:    "enable",
				},
				Components: Components{
					Gateway:            Component{Enabled: true},
					HostScanner:        Component{Enabled: true},
					Kollector:          Component{Enabled: true},
					Kubescape:          Component{Enabled: true},
					KubescapeScheduler: Component{Enabled: true},
					Kubevuln:           Component{Enabled: true},
					KubevulnScheduler:  Component{Enabled: true},
					NodeAgent:          Component{Enabled: true},
					Operator:           Component{Enabled: true},
					OtelCollector:      Component{Enabled: true},
					Storage:            Component{Enabled: true},
				},
				Configurations: Configurations{
					Persistence: "enable",
					Server: Server{
						URL: "foo.com",
					},
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
				Namespace:                "kubescape",
				RestAPIPort:              "4002",
				CleanUpRoutineInterval:   10 * time.Minute,
				ConcurrencyWorkers:       3,
				TriggerSecurityFramework: false,
				MatchingRulesFilename:    "/etc/config/matchingRules.json",
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
			},
			wantErr: true,
		},
		{
			name: "no discovery, no account: error",
			args: args{
				clusterConfig: armometadata.ClusterConfig{
					ClusterName: "foo",
				},
				components: CapabilitiesConfig{},
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
			},
			wantErr: true,
		},
		{
			name: "no discovery, account: no error",
			args: args{
				clusterConfig: armometadata.ClusterConfig{
					AccountID:   "123",
					ClusterName: "foo",
				},
				components: CapabilitiesConfig{},
			},
		},
		{
			name: "discovery, account: no error",
			args: args{
				clusterConfig: armometadata.ClusterConfig{
					AccountID:   "123",
					ClusterName: "foo",
				},
				components: CapabilitiesConfig{
					Components: Components{ServiceDiscovery: Component{Enabled: true}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.args.clusterConfig, tt.args.components)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
