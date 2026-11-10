# SBOM export to Dependency-Track

## Overview

With the `sbomExport` capability, the operator sends the SBOMs node-agent
stores (`SBOMSyft` objects, from `nodeSbomGeneration`) to
[Dependency-Track](https://dependencytrack.org), one project per running image
and namespace, and keeps them current as workloads change. It needs neither
kubevuln nor registry access: the SBOMs are the ones node-agent builds from the
image layers on each node.

## How it works

The exporter is fed by `SBOMWatch`, the operator's watch of running pods and
`SBOMSyft` objects, which also starts when kubevuln is off but `sbomExport` is
on. An image is exported when its SBOM becomes ready, when a pod starts with an
image whose SBOM is ready, and on every resync (`resyncInterval`, one hour by
default), which compares every running image with Dependency-Track. The resync
catches up after Dependency-Track was unreachable or the operator restarted.

For each namespace the image runs in, the exporter looks up its project. If the
project's last BOM import is not older than the `SBOMSyft`, the image is only
marked as the project's latest version. Otherwise the exporter reads the
`SBOMSyft`, converts its syft document to CycloneDX JSON (1.6) with syft, the
way `syft convert` does, and uploads it. An image that runs in several
namespaces is converted once.

An image stays counted as running in a namespace for one resync interval after
its last pod there ended, so the image of a short Job is still exported once
its SBOM is ready. Namespaces the operator skips (`excludeNamespaces`,
`includeNamespaces`, their regex forms) are not exported.

## Projects in Dependency-Track

```text
<root> : current                              collection, adds up its namespaces
└── <root>/<namespace> : current              collection, adds up the latest version of each image
    └── <root>/<namespace>/<repository> : <tag>
```

`<root>` is `dependencyTrack.rootProject`, by default the cluster name. The two
collection levels use the fixed version `current`, because Dependency-Track 5
refuses a project without a version. An image referenced only by digest gets
the first 12 characters of the digest as its version. Projects of images that
stopped running are left as they are.

The tree needs Dependency-Track 4.13 or later (collection projects).

## Configuration

`capabilities.json`:

```json
{
  "capabilities": {
    "nodeSbomGeneration": "enable",
    "sbomExport": "enable"
  }
}
```

`config.json`:

```json
{
  "sbomExport": {
    "resyncInterval": "1h",
    "dependencyTrack": {
      "url": "https://dtrack.example.com",
      "apiKeyFile": "/etc/sbom-export/api-key",
      "rootProject": ""
    }
  }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `sbomExport.resyncInterval` | `1h` | How often every running image is compared with Dependency-Track; also how long an image counts as running after its last pod ended |
| `sbomExport.dependencyTrack.url` | *required* | Base URL of the Dependency-Track API server |
| `sbomExport.dependencyTrack.apiKeyFile` | `/etc/sbom-export/api-key` | File holding the API key, read on every request, so a rotated Secret needs no restart |
| `sbomExport.dependencyTrack.rootProject` | cluster name | Root project of the tree |

Without `nodeSbomGeneration`, or with an invalid configuration, the operator
logs why and runs without the export.

The team that owns the API key needs `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`,
`VIEW_PORTFOLIO` and `PORTFOLIO_MANAGEMENT`; on Dependency-Track 5,
`PORTFOLIO_MANAGEMENT_CREATE` and `PORTFOLIO_MANAGEMENT_UPDATE` replace the
last one. They create the collection projects and set their collection logic.

## Logs

Every image sent logs `sent SBOM to Dependency-Track` with its project and
version. Each resync logs what happened since the previous one: sent,
unchanged, skipped because no ready SBOM exists yet, and failed. A failed
export is retried with backoff, up to five times, and then at the next resync.
A refused API key is logged once per resync, with the permissions above.
