package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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
