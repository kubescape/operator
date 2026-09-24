package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestLoadNamespaceFilterConfigMapName(t *testing.T) {
	for _, name := range []string{"", "namespace-filters"} {
		t.Run(name, func(t *testing.T) {
			viper.Reset()
			defer viper.Reset()
			dir := t.TempDir()
			doc := `{}`
			if name != "" {
				doc = `{"namespaceFilterConfigMapName":"namespace-filters"}`
			}
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(doc), 0600))
			cfg, err := LoadConfig(dir)
			require.NoError(t, err)
			require.Equal(t, name, cfg.NamespaceFilterConfigMapName)
		})
	}
}

func TestNamespaceFilterUpdates(t *testing.T) {
	cfg, err := NewOperatorConfig(CapabilitiesConfig{}, armometadata.ClusterConfig{}, nil, Config{ExcludeNamespaces: []string{"system"}})
	require.NoError(t, err)
	for _, tt := range []struct {
		doc              string
		payments, system bool
	}{
		{`{"includeNamespaces":[],"excludeNamespaces":["payments"]}`, true, false},
		{`{"includeNamespaces":"payments","excludeNamespaces":"payments,system"}`, false, true},
		{`{"includeNamespaces":[],"excludeNamespaces":[],"includeNamespacesRegex":["^pay.*$"]}`, false, true},
		{`{"includeNamespaces":[],"excludeNamespaces":[],"excludeNamespacesRegex":"^pay.*$"}`, true, false},
		{`{"includeNamespaces":"","excludeNamespaces":""}`, false, false},
	} {
		changed, err := cfg.UpdateNamespaceFilters([]byte(tt.doc))
		require.NoError(t, err)
		require.True(t, changed)
		require.Equal(t, tt.payments, cfg.SkipNamespace("payments"))
		require.Equal(t, tt.system, cfg.SkipNamespace("system"))
		changed, err = cfg.UpdateNamespaceFilters([]byte(tt.doc))
		require.NoError(t, err)
		require.False(t, changed)
	}
}

func TestNamespaceFilterRejectsInvalidReplacement(t *testing.T) {
	cfg, err := NewOperatorConfig(CapabilitiesConfig{}, armometadata.ClusterConfig{}, nil, Config{ExcludeNamespaces: []string{"payments"}})
	require.NoError(t, err)
	for _, doc := range []string{
		`{`, `null`, `[]`, `{}`, `{"includeNamespaces":[]}`, `{"excludeNamespaces":[]}`,
		`{"includeNamespaces":null,"excludeNamespaces":[]}`,
		`{"includeNamespaces":[],"excludeNamespaces":123}`,
		`{"includeNamespaces":true,"excludeNamespaces":[]}`,
		`{"includeNamespaces":[],"excludeNamespaces":[1]}`,
		`{"includeNamespaces":[],"excludeNamespaces":[null]}`,
		`{"includeNamespaces":[],"excludeNamespaces":{},"includeNamespacesRegex":[]}`,
		`{"includeNamespaces":[],"excludeNamespaces":[],"includeNamespacesRegex":null}`,
		`{"includeNamespaces":[],"excludeNamespaces":[],"excludeNamespacesRegex":["["]}`,
		`{"includeNamespaces":[],"excludeNamespaces":[],"includeNamespacesRegex":"["}`,
		`{"includeNamespaces":[],"excludeNamespaces":[],"excludeNamespace":[]}`,
		`{"includeNamespaces":[],"excludeNamespaces":[]} {}`,
	} {
		t.Run(doc, func(t *testing.T) {
			before := cfg.namespaceFilter.Load()
			changed, err := cfg.UpdateNamespaceFilters([]byte(doc))
			require.Error(t, err)
			require.False(t, changed)
			require.Same(t, before, cfg.namespaceFilter.Load())
			require.True(t, cfg.SkipNamespace("payments"))
		})
	}
}

func TestNamespaceFilterSnapshotsAreOwned(t *testing.T) {
	input := Config{IncludeNamespaces: []string{"payments"}, ExcludeNamespaces: []string{"system"}, IncludeNamespacesRegex: []string{"^prod$"}, ExcludeNamespacesRegex: []string{"^dev$"}}
	cfg, err := NewOperatorConfig(CapabilitiesConfig{}, armometadata.ClusterConfig{}, nil, input)
	require.NoError(t, err)
	input.IncludeNamespaces[0] = "changed"
	for _, getter := range []func() []string{cfg.IncludeNamespaces, cfg.ExcludeNamespaces, cfg.IncludeNamespacesRegex, cfg.ExcludeNamespacesRegex} {
		values := getter()
		original := values[0]
		values[0] = "changed"
		require.Equal(t, original, getter()[0])
	}
	require.False(t, cfg.SkipNamespace("payments"))
	require.True(t, cfg.SkipNamespace("changed"))
}

func TestNamespaceFilterConcurrentUpdates(t *testing.T) {
	cfg, err := NewOperatorConfig(CapabilitiesConfig{}, armometadata.ClusterConfig{}, nil, Config{})
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				// Both complete snapshots allow payments. A mixed snapshot could deny it.
				if cfg.SkipNamespace("payments") {
					t.Error("observed mixed snapshot")
				}
				cfg.IncludeNamespaces()
				cfg.ExcludeNamespaces()
				cfg.IncludeNamespacesRegex()
				cfg.ExcludeNamespacesRegex()
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		_, err := cfg.UpdateNamespaceFilters([]byte(`{"includeNamespaces":["payments"],"excludeNamespaces":["payments"]}`))
		require.NoError(t, err)
		_, err = cfg.UpdateNamespaceFilters([]byte(`{"includeNamespaces":[],"excludeNamespaces":[]}`))
		require.NoError(t, err)
	}
	wg.Wait()
}
