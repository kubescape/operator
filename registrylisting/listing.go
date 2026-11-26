// Package registrylisting lists the repositories of a container image registry. It is
// shared by the registry check (which fills the repository dropdown in the UI) and the
// registry scan (which, with ScanAllRepositories set, lists repositories at run time).
package registrylisting

import (
	"context"
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/registryx/interfaces"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// listECR is a variable so tests can replace the AWS SDK call.
var listECR = ListECRRepositories

// ListAllRepositories returns every repository in the registry. ECR is listed with the
// AWS SDK, because its _catalog endpoint is unreliable, and never uses client (callers
// may pass nil for ECR); every other provider needs the registryx client.
func ListAllRepositories(ctx context.Context, client interfaces.RegistryClient, registry armotypes.ContainerImageRegistry) ([]string, error) {
	provider := registry.GetBase().Provider
	if provider == armotypes.AWS {
		return listECR(ctx, registry)
	}
	if client == nil {
		return nil, fmt.Errorf("no registry client for %s registry", provider)
	}
	return client.GetAllRepositories(ctx)
}

// ListECRRepositories lists an ECR registry's repositories with the AWS SDK. It
// authenticates the same way registryx's ECR client does (see ecrConfig).
func ListECRRepositories(ctx context.Context, registry armotypes.ContainerImageRegistry) ([]string, error) {
	awsRegistry, ok := registry.(*armotypes.AWSImageRegistry)
	if !ok {
		return nil, fmt.Errorf("registry is not an AWS registry")
	}
	region, err := ecrRegion(awsRegistry)
	if err != nil {
		return nil, err
	}

	awsConfig, err := ecrConfig(ctx, awsRegistry, region)
	if err != nil {
		return nil, err
	}

	repositories, err := listECRPages(ctx, ecr.NewFromConfig(awsConfig))
	if err != nil {
		return nil, err
	}
	logger.L().Info("Successfully retrieved ECR repositories", helpers.Int("count", len(repositories)))
	return repositories, nil
}

// ecrConfig picks the registry's credentials the way registryx's ECR client does: its
// access keys when set, else its role (assumed through STS) when set, else the
// operator's default AWS credential chain.
func ecrConfig(ctx context.Context, registry *armotypes.AWSImageRegistry, region string) (aws.Config, error) {
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if registry.AccessKeyID != "" && registry.SecretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(registry.AccessKeyID, registry.SecretAccessKey, "")))
	}

	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %w", err)
	}

	if (registry.AccessKeyID == "" || registry.SecretAccessKey == "") && registry.RoleARN != "" {
		assumeRole := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsConfig), registry.RoleARN,
			func(o *stscreds.AssumeRoleOptions) { o.RoleSessionName = ecrRoleSessionName })
		awsConfig.Credentials = aws.NewCredentialsCache(assumeRole)
	}
	return awsConfig, nil
}

const ecrRoleSessionName = "kubescape-registry-listing"

type ecrDescribeRepositoriesAPI interface {
	DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
}

// listECRPages pages through DescribeRepositories. When ECR rejects a NextToken, the
// listing starts over from the first page once, discarding what it collected, so no
// repository is returned twice; a second rejection is an error.
func listECRPages(ctx context.Context, api ecrDescribeRepositoriesAPI) ([]string, error) {
	var repositories []string
	var nextToken *string
	restarted := false

	for {
		result, err := api.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
			MaxResults: aws.Int32(100),
			NextToken:  nextToken,
		})
		if err != nil {
			if nextToken != nil && !restarted && isNextTokenError(err) {
				logger.L().Warning("ECR rejected the NextToken, listing again from the first page", helpers.Error(err))
				restarted = true
				repositories = nil
				nextToken = nil
				continue
			}
			return nil, fmt.Errorf("ECR API error: %w", err)
		}

		for _, repo := range result.Repositories {
			if repo.RepositoryName != nil {
				repositories = append(repositories, *repo.RepositoryName)
			}
		}

		if result.NextToken == nil {
			return repositories, nil
		}
		nextToken = result.NextToken
	}
}

func isNextTokenError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "NextToken") ||
		strings.Contains(msg, "Invalid next token provided") ||
		strings.Contains(msg, "Invalid parameter at 'NextToken'")
}

// FillECRRegion sets an ECR registry's RegistryRegion from its RegistryURI when the
// region is empty, the way armotypes' Validate does when a registry is created, so the
// registryx client (which resolves images in RegistryRegion) and the listing use the same
// region. Other registries, and an ECR registry whose URI has no region, are left as is.
func FillECRRegion(registry armotypes.ContainerImageRegistry) {
	awsRegistry, ok := registry.(*armotypes.AWSImageRegistry)
	if !ok || awsRegistry.RegistryRegion != "" {
		return
	}
	awsRegistry.RegistryRegion = extractRegionFromECRURI(awsRegistry.RegistryURI)
}

// ecrRegion returns the region to list in: the saved RegistryRegion, which registryx's
// ECR client also uses to resolve images, else the region in RegistryURI. A saved region
// that disagrees with the URI is an error, since listing and image resolution would then
// look at different regions.
func ecrRegion(registry *armotypes.AWSImageRegistry) (string, error) {
	uriRegion := extractRegionFromECRURI(registry.RegistryURI)
	switch {
	case registry.RegistryRegion != "" && uriRegion != "" && registry.RegistryRegion != uriRegion:
		return "", fmt.Errorf("ECR registry region %q does not match the region in its URI %s (%q)",
			registry.RegistryRegion, registry.RegistryURI, uriRegion)
	case registry.RegistryRegion != "":
		return registry.RegistryRegion, nil
	case uriRegion != "":
		return uriRegion, nil
	default:
		return "", fmt.Errorf("failed to extract region from ECR URI: %s", registry.RegistryURI)
	}
}

func extractRegionFromECRURI(uri string) string {
	parts := strings.Split(uri, ".")
	if len(parts) >= 4 && parts[1] == "dkr" && parts[2] == "ecr" {
		return parts[3]
	}
	return ""
}
