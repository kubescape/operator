package mainhandler

import (
	"context"
	"errors"
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/registryx/interfaces"
	dockerregistry "github.com/docker/docker/api/types/registry"
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

func TestPopulateGitLabRepositoriesForScan(t *testing.T) {
	t.Run("gitlab scan-all populates repositories", func(t *testing.T) {
		registry := &apitypes.GitlabImageRegistry{
			BaseContainerImageRegistry: apitypes.BaseContainerImageRegistry{
				Provider: apitypes.Gitlab,
			},
		}
		client := &fakeRegistryClient{repositories: []string{"group/service", "group/worker"}}

		err := populateGitLabRepositoriesForScan(context.Background(), client, registry)

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

		err := populateGitLabRepositoriesForScan(context.Background(), client, registry)

		require.NoError(t, err)
		assert.Equal(t, 0, client.getAllCalls)
		assert.Equal(t, []string{"group/service"}, registry.Repositories)
	})

	t.Run("non-gitlab scan-all skips lookup", func(t *testing.T) {
		registry := &apitypes.HarborImageRegistry{
			BaseContainerImageRegistry: apitypes.BaseContainerImageRegistry{
				Provider: apitypes.Harbor,
			},
		}
		client := &fakeRegistryClient{repositories: []string{"project/app"}}

		err := populateGitLabRepositoriesForScan(context.Background(), client, registry)

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

		err := populateGitLabRepositoriesForScan(context.Background(), client, registry)

		require.Error(t, err)
		assert.Equal(t, 1, client.getAllCalls)
		assert.ErrorContains(t, err, "failed to get GitLab repositories")
		assert.Empty(t, registry.Repositories)
	})
}
