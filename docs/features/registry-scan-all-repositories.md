# Registry scan: all repositories

## Overview

A registry scan normally scans the repositories saved when the registry was set up. When
the registry has `scanAllRepositories: true`, the operator lists the registry's
repositories at the start of every run instead, so repositories created after the scan
was saved are scanned too.

The flag is `ScanAllRepositories` on armoapi-go's `BaseContainerImageRegistry`. It travels
in the `scanRegistryV2` request stored in the registry's ConfigMap, next to the saved
`repositories` list.

## How it works

`scanRegistriesV2` (`mainhandler/vulnscan.go`) builds the registryx client, then calls
`resolveRepositoriesForScan`:

- With `scanAllRepositories` set, it lists all repositories and replaces the saved list.
- A GitLab registry saved with an empty list is listed the same way, as before.
- Otherwise the saved list is used unchanged.

`GetImagesToScan` then resolves the latest tag of each repository, and each image is sent
to kubevuln as usual.

Listing goes through `registrylisting.ListAllRepositories`, which the registry check
(`watcher/registryhandler.go`, the repository list shown when a registry is set up) also
uses:

| Provider | How repositories are listed |
| --- | --- |
| AWS ECR | AWS SDK `DescribeRepositories`, paged with `NextToken` (ECR's `_catalog` endpoint is unreliable). Credentials match registryx's ECR client: the registry's access keys, else its `roleARN` assumed through STS, else the operator's default AWS credentials. If ECR rejects a `NextToken`, listing restarts from the first page once, then fails. The region is the saved `registryRegion`, which registryx also uses to resolve images, else the region in `registryURI`; a registry whose two regions disagree fails to list. |
| Quay, Harbor, Azure, Google, Nexus, GitLab | registryx `GetAllRepositories`. For GitLab this needs registryx with armosec/registryx#31, which reads every page of each project's repositories and fails when a project can't be read, instead of returning a partial list. |

## Failure behavior

- A listing error fails the run: the registry's scan status is set to `Failed` with
  `failed to prepare registry scan: failed to list repositories: <cause>`.
- A registry with no repositories ends the run as `Completed` with nothing scanned, the
  same as any run with no images.

## Compatibility

The backend always sends the current repository list with the flag. An operator that
predates this field ignores the flag and scans that saved list.
