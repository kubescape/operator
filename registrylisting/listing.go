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
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// listECR is a variable so tests can replace the AWS SDK call.
var listECR = ListECRRepositories

// ListAllRepositories returns every repository in the registry. ECR is listed with the
// AWS SDK, because its _catalog endpoint is unreliable; every other provider uses the
// registryx client.
func ListAllRepositories(ctx context.Context, client interfaces.RegistryClient, registry armotypes.ContainerImageRegistry) ([]string, error) {
	if registry.GetBase().Provider == armotypes.AWS {
		return listECR(ctx, registry)
	}
	return client.GetAllRepositories(ctx)
}

// ListECRRepositories lists an ECR registry's repositories with the AWS SDK, paging with
// NextToken. It uses the registry's access keys when set, else the default AWS
// credential chain.
func ListECRRepositories(ctx context.Context, registry armotypes.ContainerImageRegistry) ([]string, error) {
	awsRegistry, ok := registry.(*armotypes.AWSImageRegistry)
	if !ok {
		return nil, fmt.Errorf("registry is not an AWS registry")
	}
	region := extractRegionFromECRURI(awsRegistry.RegistryURI)
	if region == "" {
		return nil, fmt.Errorf("failed to extract region from ECR URI: %s", awsRegistry.RegistryURI)
	}

	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Use explicit credentials if provided
	if awsRegistry.AccessKeyID != "" && awsRegistry.SecretAccessKey != "" {
		awsConfig.Credentials = credentials.NewStaticCredentialsProvider(
			awsRegistry.AccessKeyID,
			awsRegistry.SecretAccessKey,
			"",
		)
	}

	ecrClient := ecr.NewFromConfig(awsConfig)
	var allRepositories []string
	var nextToken *string

	for {
		input := &ecr.DescribeRepositoriesInput{
			MaxResults: aws.Int32(100),
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		result, err := ecrClient.DescribeRepositories(ctx, input)
		if err != nil {
			// Retry without NextToken if ECR returns a NextToken-related error
			if strings.Contains(err.Error(), "NextToken") ||
				strings.Contains(err.Error(), "Invalid next token provided") ||
				strings.Contains(err.Error(), "Invalid parameter at 'NextToken'") {
				logger.L().Warning("ECR NextToken error detected, retrying without token", helpers.Error(err))
				nextToken = nil
				continue
			}
			return nil, fmt.Errorf("ECR API error: %w", err)
		}

		for _, repo := range result.Repositories {
			if repo.RepositoryName != nil {
				allRepositories = append(allRepositories, *repo.RepositoryName)
			}
		}

		if result.NextToken == nil {
			break
		}
		nextToken = result.NextToken
	}

	logger.L().Info("Successfully retrieved ECR repositories", helpers.Int("count", len(allRepositories)))
	return allRepositories, nil
}

func extractRegionFromECRURI(uri string) string {
	parts := strings.Split(uri, ".")
	if len(parts) >= 4 && parts[1] == "dkr" && parts[2] == "ecr" {
		return parts[3]
	}
	return ""
}
