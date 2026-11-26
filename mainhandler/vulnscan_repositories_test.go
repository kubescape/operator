package mainhandler

import (
	"context"
	"errors"
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/registryx/interfaces"
	dockerregistry "github.com/moby/moby/api/types/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ interfaces.RegistryClient = (*fakeRegistryClient)(nil)

type fakeRegistryClient struct {
	repositories []string
	getAllErr    error
	getAllCalls  int
}

func (f *fakeRegistryClient) GetAllRepositories(_ context.Context) ([]string, error) {
	f.getAllCalls++
	if f.getAllErr != nil {
		return nil, f.getAllErr
	}
	return append([]string(nil), f.repositories...), nil
}

func (f *fakeRegistryClient) GetImagesToScan(context.Context) (map[string]string, error) {
	return nil, nil
}

func (f *fakeRegistryClient) GetDockerAuth() (*dockerregistry.AuthConfig, error) {
	return &dockerregistry.AuthConfig{}, nil
}

func TestResolveRepositoriesForScan(t *testing.T) {
	t.Run("gitlab scan-all populates repositories", func(t *testing.T) {
		registry := &apitypes.GitlabImageRegistry{
			BaseContainerImageRegistry: apitypes.BaseContainerImageRegistry{
				Provider: apitypes.Gitlab,
			},
		}
		client := &fakeRegistryClient{repositories: []string{"group/service", "group/worker"}}

		err := resolveRepositoriesForScan(context.Background(), client, registry)

		require.NoError(t, err)
		assert.Equal(t, 1, client.getAllCalls)
		assert.Equal(t, []string{"group/service", "group/worker"}, registry.Repositories)
	})

	t.Run("gitlab with selected repositories skips lookup", func(t *testing.T) {
		registry := &apitypes.GitlabImageRegistry{
			BaseContainerImageRegistry: apitypes.BaseContainerImageRegistry{
				Provider:     apitypes.Gitlab,
				Repositories: []string{"group/service"},
			},
		}
		client := &fakeRegistryClient{repositories: []string{"group/worker"}}

		err := resolveRepositoriesForScan(context.Background(), client, registry)

		require.NoError(t, err)
		assert.Equal(t, 0, client.getAllCalls)
		assert.Equal(t, []string{"group/service"}, registry.Repositories)
	})

	t.Run("non-gitlab empty list without the flag skips lookup", func(t *testing.T) {
		registry := &apitypes.HarborImageRegistry{
			BaseContainerImageRegistry: apitypes.BaseContainerImageRegistry{
				Provider: apitypes.Harbor,
			},
		}
		client := &fakeRegistryClient{repositories: []string{"project/app"}}

		err := resolveRepositoriesForScan(context.Background(), client, registry)

		require.NoError(t, err)
		assert.Equal(t, 0, client.getAllCalls)
		assert.Empty(t, registry.Repositories)
	})

	t.Run("gitlab scan-all surfaces lookup errors", func(t *testing.T) {
		registry := &apitypes.GitlabImageRegistry{
			BaseContainerImageRegistry: apitypes.BaseContainerImageRegistry{
				Provider: apitypes.Gitlab,
			},
		}
		client := &fakeRegistryClient{getAllErr: errors.New("boom")}

		err := resolveRepositoriesForScan(context.Background(), client, registry)

		require.Error(t, err)
		assert.Equal(t, 1, client.getAllCalls)
		assert.ErrorContains(t, err, "failed to list repositories")
		assert.Empty(t, registry.Repositories)
	})

	t.Run("scan-all flag replaces the saved list", func(t *testing.T) {
		registry := &apitypes.QuayImageRegistry{
			BaseContainerImageRegistry: apitypes.BaseContainerImageRegistry{
				Provider:            apitypes.Quay,
				Repositories:        []string{"org/old"},
				ScanAllRepositories: true,
			},
		}
		client := &fakeRegistryClient{repositories: []string{"org/old", "org/new"}}

		err := resolveRepositoriesForScan(context.Background(), client, registry)

		require.NoError(t, err)
		assert.Equal(t, 1, client.getAllCalls)
		assert.Equal(t, []string{"org/old", "org/new"}, registry.Repositories)
	})

	t.Run("without the flag the saved list is kept", func(t *testing.T) {
		registry := &apitypes.QuayImageRegistry{
			BaseContainerImageRegistry: apitypes.BaseContainerImageRegistry{
				Provider:     apitypes.Quay,
				Repositories: []string{"org/old"},
			},
		}
		client := &fakeRegistryClient{repositories: []string{"org/old", "org/new"}}

		err := resolveRepositoriesForScan(context.Background(), client, registry)

		require.NoError(t, err)
		assert.Equal(t, 0, client.getAllCalls)
		assert.Equal(t, []string{"org/old"}, registry.Repositories)
	})

	t.Run("scan-all flag surfaces listing errors", func(t *testing.T) {
		registry := &apitypes.QuayImageRegistry{
			BaseContainerImageRegistry: apitypes.BaseContainerImageRegistry{
				Provider:            apitypes.Quay,
				Repositories:        []string{"org/old"},
				ScanAllRepositories: true,
			},
		}
		client := &fakeRegistryClient{getAllErr: errors.New("unauthorized")}

		err := resolveRepositoriesForScan(context.Background(), client, registry)

		require.Error(t, err)
		assert.ErrorContains(t, err, "failed to list repositories")
		assert.ErrorContains(t, err, "unauthorized")
		assert.Equal(t, []string{"org/old"}, registry.Repositories)
	})

	t.Run("scan-all flag on an empty registry leaves no repositories", func(t *testing.T) {
		registry := &apitypes.QuayImageRegistry{
			BaseContainerImageRegistry: apitypes.BaseContainerImageRegistry{
				Provider:            apitypes.Quay,
				Repositories:        []string{"org/deleted"},
				ScanAllRepositories: true,
			},
		}
		client := &fakeRegistryClient{repositories: []string{}}

		err := resolveRepositoriesForScan(context.Background(), client, registry)

		require.NoError(t, err)
		assert.Empty(t, registry.Repositories)
	})
}
