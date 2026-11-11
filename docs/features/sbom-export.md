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
project's last BOM import is not older than the `SBOMSyft`, and node-agent has
not rebuilt the SBOM since, the image is only marked as the project's latest
version. Otherwise the exporter reads the `SBOMSyft`, converts its syft
document to CycloneDX JSON (1.6) with syft, the way `syft convert` does, and
uploads it. An image that runs in several namespaces is converted once.

node-agent rebuilds the SBOM of a running image when its own version changes,
and replaces the document in the same `SBOMSyft`. The exporter records the
node-agent version of each upload (`kubescape.io/tool-version`) in the project
property `kubescape/sbom-tool-version`, and sends the SBOM again when it
differs.

An image stays counted as running in a namespace for one resync interval after
its last pod there ended, so the image of a short Job is still exported once
its SBOM is ready. The operator keeps this in memory: the image of a Job that
ended shortly before an operator restart is not exported, unless it runs again.
Namespaces the operator skips (`excludeNamespaces`, `includeNamespaces`, their
regex forms) are not exported.

## Projects in Dependency-Track

By default each cluster gets a tree:

```text
<cluster> : current                              collection, adds up its namespaces
└── <cluster>/<namespace> : current              collection, adds up the latest version of each image
    └── <cluster>/<namespace>/<repository> : <tag>
```

The collection levels use the fixed version `current`, because
Dependency-Track 5 refuses a project without a version. An image referenced
only by digest gets the first 12 characters of the digest as its version.
Projects of images that stopped running are left as they are. The tree needs
Dependency-Track 4.13 or later (collection projects).

### Changing the layout

The tree is built from three projects per image, each a Go template, in the
same style as the node-agent autoscaler's DaemonSet template:

- the **project** of the image, uploaded with its BOM;
- its **parent**, a collection;
- the **root project**, under which the operator creates parents it creates.

Templates can use `.Cluster`, `.Namespace`, `.Repository`, `.Tag` and
`.Labels`, the namespace's labels, for example
`{{ .Cluster }}/{{ index .Labels "team" }}`.

A namespace can override any of them with annotations. Each one replaces only
the setting it names:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: payments
  annotations:
    kubescape.io/dtrack-root-project: "Finance:current"   # name:version, or a project UUID
    kubescape.io/dtrack-root-project-create: "false"
    kubescape.io/dtrack-parent: "Payments Team:current"
    kubescape.io/dtrack-parent-create: "true"
    kubescape.io/dtrack-project-name: "{{ .Repository }}"
```

With the default settings for every other namespace, this gives:

```text
prod-cluster : current                    ← created by the operator (default root)
└── prod-cluster/team-a : current
    └── prod-cluster/team-a/nginx : 1.27
Finance : current                         ← yours, never modified
└── Payments Team : current               ← created by the operator under Finance
    ├── payments-api : 1.4
    └── payments-worker : 2.0
```

Rules:

| Situation | What the operator does |
|-----------|------------------------|
| The parent exists | Uploads the image's project under it. The root is not used. |
| The parent is missing, `create` is true | Creates it as a collection under the root, creating the root too when it is missing and may be created. |
| A project is missing and `create` is false, or it is named by a UUID that does not exist | Logs it once per resync and skips that namespace's images. Nothing is created. |
| A project exists that the operator did not create | Uses it, but never changes it: no collection logic, no BOM, no move. The operator tags what it creates with `managed-by:kubescape`; to let it take over projects created another way, for example by an earlier exporter, add that tag to them. |
| The image's project exists and was not created by the operator | Skips the image and logs a conflict, instead of replacing someone's BOM. |
| Two running images resolve to the same project and version | Uploads the first and skips the second, logging a conflict: one project version holds one BOM. The operator records each project's image digest in the project property `kubescape/image-digest`. When the first image stops running, the second takes the project over. |
| A namespace's labels or `kubescape.io/dtrack-*` annotations change | Moves the projects it created for that namespace's running images to their new place with a PATCH, so their history in Dependency-Track goes with them. When only the root changes, it moves the namespace's parent, also when none of its images can be exported. When the new place names a project that is missing and may not be created, the move waits and is tried again at every resync. A change made while the operator is not running is not seen; those images start new projects. |
| A template or annotation cannot be used (a typo, an unknown field, an empty result, a create flag that is not `true` or `false`) | Logs it once per resync and skips that namespace's images. Invalid default templates in `config.json` turn the export off at startup, with the reason in the log. |

## SBOM size

Converting an SBOM takes about nine times its size in memory, one image at a
time. Measured with node-agent's cataloger settings, the SBOM of
`nvcr.io/nvidia/pytorch:26.10-py3` (24.9 MiB) peaked at 176 MiB of heap and the
one of `quay.io/jupyter/all-spark-notebook` (33.9 MiB) at 291 MiB, both without
a `GOMEMLIMIT`.

SBOMs larger than `sbomExport.maxSBOMSize` (10 MiB by default) are skipped and
logged once per resync. The operator checks the `kubescape.io/resource-size`
annotation before it reads the SBOM, stops reading an `SBOMSyft` that is more
than 1 MiB over the limit, and checks the document's length after.

node-agent has its own `maxSBOMSize`, 20 MiB by default: it marks a larger SBOM
`too-large` and stores it without its content, so there is nothing to export.
To export bigger SBOMs, raise three settings together:

1. node-agent's `maxSBOMSize`, so it keeps them;
2. `sbomExport.maxSBOMSize`, so the operator converts them;
3. the operator's memory limit, to at least nine times `sbomExport.maxSBOMSize`
   plus 64 MiB for the rest of the operator. The Helm chart sets `GOMEMLIMIT`
   from the limit (`operator.gomemlimitPercentage`, 80% by default).

| `sbomExport.maxSBOMSize` | Memory limit it needs | Operator limit |
|--------------------------|-----------------------|----------------|
| 10 MiB (default) | 154 MiB | 300Mi, the chart's default |
| 20 MiB | 244 MiB | 300Mi, the chart's default |
| 32 MiB | 352 MiB | 512Mi |

The Helm chart warns in the `ks-capabilities` ConfigMap when the operator's
memory limit is below this rule.

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

`config.json`, with the defaults:

```json
{
  "sbomExport": {
    "resyncInterval": "1h",
    "maxSBOMSize": 10485760,
    "dependencyTrack": {
      "url": "https://dtrack.example.com",
      "apiKeyFile": "/etc/sbom-export/api-key",
      "rootProject": {"name": "{{ .Cluster }}", "version": "current", "create": true},
      "project": {
        "name": "{{ .Cluster }}/{{ .Namespace }}/{{ .Repository }}",
        "version": "{{ .Tag }}",
        "parent": {"name": "{{ .Cluster }}/{{ .Namespace }}", "version": "current", "create": true}
      }
    }
  }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `sbomExport.resyncInterval` | `1h` | How often every running image is compared with Dependency-Track; also how long an image counts as running after its last pod ended |
| `sbomExport.maxSBOMSize` | `10485760` (10 MiB) | Largest SBOM, in bytes, the operator converts; see [SBOM size](#sbom-size) for the memory it needs |
| `sbomExport.dependencyTrack.url` | *required* | Base URL of the Dependency-Track API server |
| `sbomExport.dependencyTrack.apiKeyFile` | `/etc/sbom-export/api-key` | File holding the API key, read on every request, so a rotated Secret needs no restart |
| `sbomExport.dependencyTrack.rootProject.{name,version,create}` | `{{ .Cluster }}`, `current`, `true` | The root project, where created parents go |
| `sbomExport.dependencyTrack.project.{name,version}` | `{{ .Cluster }}/{{ .Namespace }}/{{ .Repository }}`, `{{ .Tag }}` | The image's project |
| `sbomExport.dependencyTrack.project.parent.{name,version,create}` | `{{ .Cluster }}/{{ .Namespace }}`, `current`, `true` | The image project's parent |

Without `nodeSbomGeneration`, or with an invalid configuration, the operator
logs why and runs without the export.

## Permissions in Dependency-Track

The team that owns the API key needs `VIEW_PORTFOLIO` to look projects up,
`BOM_UPLOAD` to upload, and `PORTFOLIO_MANAGEMENT` to create projects, set the
collection logic, mark the running version latest, record the image digest and
move projects; on Dependency-Track 5, `PORTFOLIO_MANAGEMENT_CREATE` and
`PORTFOLIO_MANAGEMENT_UPDATE` replace it. The operator creates each image's
project before it uploads the BOM, so `PROJECT_CREATION_UPLOAD` is not needed,
also when the layout only names existing root and parent projects. With
portfolio access control on, the team also needs access to the existing
projects the layout names. A refused call is logged with the reason
Dependency-Track gave.

## Logs

Every image sent logs `sent SBOM to Dependency-Track` with its project and
version. Each resync logs what happened since the previous one: sent,
unchanged, skipped because no ready SBOM exists yet, skipped as too large,
conflicts, skipped because the layout could not be used, moved, and failed. A
failed export is retried with backoff, up to five times, and then at the next
resync. A refused API key is logged once per resync, with the permissions above.
