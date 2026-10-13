package config

import (
	"os"
	"path/filepath"
	"testing"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestLoadControlExclusions(t *testing.T) {
	for _, tt := range []struct {
		name, input string
		want        []string
		wantError   bool
	}{
		{"absent", `{}`, nil, false},
		{"empty", `{"excludeControls":[]}`, []string{}, false},
		{"null", `{"excludeControls":null}`, nil, false},
		{"list", `{"excludeControls":["C-0069","C-0070"]}`, []string{"C-0069", "C-0070"}, false},
		{"scalar", `{"excludeControls":"C-0069"}`, nil, true},
		{"number", `{"excludeControls":[42]}`, nil, true},
		{"blank", `{"excludeControls":[" "]}`, nil, true},
		{"null entry", `{"excludeControls":[null]}`, nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(tt.input), 0600))
			got, err := LoadConfig(dir)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got.ExcludeControls)
			cfg, err := NewOperatorConfig(CapabilitiesConfig{}, utilsmetadata.ClusterConfig{}, nil, got)
			require.NoError(t, err)
			exclusions := cfg.ExcludeControls()
			require.Equal(t, tt.want, exclusions)
			if len(exclusions) > 0 {
				exclusions[0] = "changed"
				require.Equal(t, tt.want, cfg.ExcludeControls())
			}
		})
	}
}
