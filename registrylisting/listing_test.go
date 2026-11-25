package registrylisting

import (
	"context"
	"errors"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
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

func TestListAllRepositoriesUsesClientForQuay(t *testing.T) {
	registry := &armotypes.QuayImageRegistry{
		BaseContainerImageRegistry: armotypes.BaseContainerImageRegistry{Provider: armotypes.Quay},
	}
	client := &fakeRegistryClient{repositories: []string{"org/a"}}

	repositories, err := ListAllRepositories(context.Background(), client, registry)

	require.NoError(t, err)
	assert.Equal(t, []string{"org/a"}, repositories)
	assert.Equal(t, 1, client.getAllCalls)
}

func TestListAllRepositoriesUsesSDKForECR(t *testing.T) {
	original := listECR
	t.Cleanup(func() { listECR = original })
	listECR = func(_ context.Context, _ armotypes.ContainerImageRegistry) ([]string, error) {
		return []string{"repo-x"}, nil
	}
	registry := &armotypes.AWSImageRegistry{
		BaseContainerImageRegistry: armotypes.BaseContainerImageRegistry{Provider: armotypes.AWS},
		RegistryURI:                "123456789012.dkr.ecr.eu-west-1.amazonaws.com",
	}
	client := &fakeRegistryClient{repositories: []string{"from-catalog"}}

	repositories, err := ListAllRepositories(context.Background(), client, registry)

	require.NoError(t, err)
	assert.Equal(t, []string{"repo-x"}, repositories)
	assert.Equal(t, 0, client.getAllCalls)
}

func TestListAllRepositoriesReturnsClientError(t *testing.T) {
	registry := &armotypes.HarborImageRegistry{
		BaseContainerImageRegistry: armotypes.BaseContainerImageRegistry{Provider: armotypes.Harbor},
	}
	forbidden := errors.New("forbidden")
	client := &fakeRegistryClient{getAllErr: forbidden}

	_, err := ListAllRepositories(context.Background(), client, registry)

	require.ErrorIs(t, err, forbidden)
}

func TestListECRRepositoriesRejectsBadInput(t *testing.T) {
	t.Run("not an AWS registry", func(t *testing.T) {
		_, err := ListECRRepositories(context.Background(), &armotypes.QuayImageRegistry{})

		require.ErrorContains(t, err, "not an AWS registry")
	})

	t.Run("URI without a region", func(t *testing.T) {
		_, err := ListECRRepositories(context.Background(), &armotypes.AWSImageRegistry{RegistryURI: "quay.io"})

		require.ErrorContains(t, err, "failed to extract region from ECR URI: quay.io")
	})
}

func TestExtractRegionFromECRURI(t *testing.T) {
	assert.Equal(t, "eu-west-1", extractRegionFromECRURI("123456789012.dkr.ecr.eu-west-1.amazonaws.com"))
	assert.Equal(t, "", extractRegionFromECRURI("quay.io"))
}
