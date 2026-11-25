package registrylisting

import (
	"context"
	"errors"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/registryx/interfaces"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
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

// fakeECR serves pages of repository names keyed by the NextToken it receives ("" is
// the first page). tokenErrors makes a call with that token fail that many times.
type fakeECR struct {
	pages       map[string]ecr.DescribeRepositoriesOutput
	tokenErrors map[string]int
	calls       int
}

func (f *fakeECR) DescribeRepositories(_ context.Context, in *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	f.calls++
	token := aws.ToString(in.NextToken)
	if f.tokenErrors[token] > 0 {
		f.tokenErrors[token]--
		return nil, errors.New("InvalidParameterException: Invalid next token provided")
	}
	page := f.pages[token]
	return &page, nil
}

func repos(names ...string) []ecrtypes.Repository {
	out := make([]ecrtypes.Repository, 0, len(names))
	for _, n := range names {
		out = append(out, ecrtypes.Repository{RepositoryName: aws.String(n)})
	}
	return out
}

func TestListECRPages(t *testing.T) {
	twoPages := func() map[string]ecr.DescribeRepositoriesOutput {
		return map[string]ecr.DescribeRepositoriesOutput{
			"":   {Repositories: repos("a", "b"), NextToken: aws.String("t1")},
			"t1": {Repositories: repos("c")},
		}
	}

	t.Run("pages through all repositories", func(t *testing.T) {
		api := &fakeECR{pages: twoPages()}

		got, err := listECRPages(context.Background(), api)

		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b", "c"}, got)
		assert.Equal(t, 2, api.calls)
	})

	t.Run("restarts once on a NextToken error without duplicates", func(t *testing.T) {
		api := &fakeECR{pages: twoPages(), tokenErrors: map[string]int{"t1": 1}}

		got, err := listECRPages(context.Background(), api)

		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b", "c"}, got)
		assert.Equal(t, 4, api.calls)
	})

	t.Run("fails when the NextToken error repeats after the restart", func(t *testing.T) {
		api := &fakeECR{pages: twoPages(), tokenErrors: map[string]int{"t1": 5}}

		_, err := listECRPages(context.Background(), api)

		require.ErrorContains(t, err, "Invalid next token provided")
		assert.Equal(t, 4, api.calls)
	})
}

func TestECRConfigCredentials(t *testing.T) {
	// keep the developer's own AWS files and environment out of the test
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_PROFILE", "")

	t.Run("static keys win", func(t *testing.T) {
		cfg, err := ecrConfig(context.Background(), &armotypes.AWSImageRegistry{
			AccessKeyID: "AKIDTEST", SecretAccessKey: "secret", RoleARN: "arn:aws:iam::123456789012:role/scan",
		}, "eu-west-1")

		require.NoError(t, err)
		creds, err := cfg.Credentials.Retrieve(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "AKIDTEST", creds.AccessKeyID)
		assert.Equal(t, "eu-west-1", cfg.Region)
	})

	t.Run("role ARN is assumed", func(t *testing.T) {
		cfg, err := ecrConfig(context.Background(), &armotypes.AWSImageRegistry{
			RoleARN: "arn:aws:iam::123456789012:role/scan",
		}, "eu-west-1")

		require.NoError(t, err)
		assert.True(t, aws.IsCredentialsProvider(cfg.Credentials, (*stscreds.AssumeRoleProvider)(nil)))
	})

	t.Run("no keys and no role use the default chain", func(t *testing.T) {
		cfg, err := ecrConfig(context.Background(), &armotypes.AWSImageRegistry{}, "eu-west-1")

		require.NoError(t, err)
		assert.False(t, aws.IsCredentialsProvider(cfg.Credentials, (*stscreds.AssumeRoleProvider)(nil)))
	})
}
