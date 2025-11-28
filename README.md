# Kubescape Operator

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/kubescape/operator/badge)](https://securityscorecards.dev/viewer/?uri=github.com/kubescape/operator)
[![CNCF Incubating](https://img.shields.io/badge/CNCF-Incubating-blue.svg)](https://www.cncf.io/projects/kubescape/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/kubescape/operator)](https://goreportcard.com/report/github.com/kubescape/operator)

The **Kubescape Operator** is the central orchestration engine for [Kubescape](https://kubescape.io)'s in-cluster components. It coordinates security scanning operations, manages scheduled tasks, and provides a REST API for triggering actions across your Kubernetes cluster.

---

## Table of Contents

- [Why Use the Operator?](#why-use-the-operator)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Using Helm (Recommended)](#using-helm-recommended)
  - [Running Locally for Development](#running-locally-for-development)
- [Configuration](#configuration)
  - [Configuration Files](#configuration-files)
  - [Environment Variables](#environment-variables)
  - [Configuration Defaults](#configuration-defaults)
- [API Documentation](#api-documentation)
- [API Examples](#api-examples)
  - [Kubescape Configuration Scans](#kubescape-configuration-scans)
  - [Vulnerability Scans](#vulnerability-scans)
  - [Registry Scans](#registry-scans)
- [Private Registry Authentication](#private-registry-authentication)
- [Features](#features)
  - [Continuous Scanning](#continuous-scanning)
  - [Admission Controller](#admission-controller)
- [Development](#development)
  - [Building from Source](#building-from-source)
  - [VS Code Configuration](#vs-code-configuration)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Why Use the Operator?

The Kubescape Operator provides:

- 🔄 **Centralized Orchestration** - Single control plane for all Kubescape in-cluster security operations
- 🕐 **Scheduled Scanning** - CronJob-based recurring security and vulnerability scans
- 🔍 **Continuous Monitoring** - Real-time detection of configuration changes with automatic rescanning
- 🛡️ **Admission Control** - Validate workloads against security policies before deployment
- 📡 **REST API** - Programmatic access to trigger scans and manage security operations
- 🔗 **Component Integration** - Seamlessly coordinates Kubescape, Kubevuln, and other in-cluster components

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Kubernetes Cluster                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │                        kubescape namespace                            │  │
│   │                                                                       │  │
│   │  ┌─────────────┐     REST API      ┌─────────────────────────────┐   │  │
│   │  │   Client    │ ─────────────────▶│       OPERATOR              │   │  │
│   │  │  (kubectl,  │    :4002          │                             │   │  │
│   │  │   curl)     │                   │  • Command Processing       │   │  │
│   │  └─────────────┘                   │  • CronJob Management       │   │  │
│   │                                    │  • Continuous Scanning      │   │  │
│   │                                    │  • Admission Controller     │   │  │
│   │                                    └──────────┬──────────────────┘   │  │
│   │                                               │                       │  │
│   │                    ┌──────────────────────────┼──────────────────┐   │  │
│   │                    │                          │                  │   │  │
│   │                    ▼                          ▼                  ▼   │  │
│   │           ┌────────────────┐      ┌────────────────┐    ┌──────────┐│  │
│   │           │   Kubescape    │      │    Kubevuln    │    │ Storage  ││  │
│   │           │                │      │                │    │          ││  │
│   │           │ Config Scans   │      │ Vuln Scans     │    │ Results  ││  │
│   │           └────────────────┘      └────────────────┘    └──────────┘│  │
│   │                                                                       │  │
│   └──────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

Get Kubescape with the Operator running in under 5 minutes:

```bash
# 1. Add the Kubescape Helm repository
helm repo add kubescape https://kubescape.github.io/helm-charts/
helm repo update

# 2. Install Kubescape with all components
helm upgrade --install kubescape kubescape/kubescape-operator \
  -n kubescape --create-namespace \
  --set clusterName="my-cluster"

# 3. Verify the Operator is running
kubectl get pods -n kubescape -l app.kubernetes.io/name=operator

# 4. Trigger a configuration scan via port-forward
kubectl port-forward -n kubescape svc/operator 4002:4002 &

curl -X POST http://localhost:4002/v1/triggerAction \
  -H 'Content-Type: application/json' \
  -d '{
    "commands": [{
      "commandName": "kubescapeScan",
      "args": {
        "scanV1": {
          "submit": true
        }
      }
    }]
  }'
```

**Expected output:**
```json
{"commands":[{"commandName":"kubescapeScan",...}]}
```

---

## Installation

### Using Helm (Recommended)

The Kubescape Operator is deployed as part of the Kubescape Helm chart. Visit the [Kubescape Helm Charts repository](https://github.com/kubescape/helm-charts/) for detailed installation options.

```bash
# Basic installation
helm upgrade --install kubescape kubescape/kubescape-operator \
  -n kubescape --create-namespace \
  --set clusterName="my-cluster"

# With cloud connection (for Kubescape Cloud users)
helm upgrade --install kubescape kubescape/kubescape-operator \
  -n kubescape --create-namespace \
  --set clusterName="my-cluster" \
  --set account="your-account-id" \
  --set accessKey="your-access-key"
```

### Running Locally for Development

For development or testing, you can run the Operator locally:

#### Prerequisites
- A running Kubernetes cluster (minikube, kind, etc.)
- `kubectl` configured to access your cluster
- Go 1.24+ installed

#### Steps

1. **Install Kubescape in-cluster components:**
   ```bash
   helm upgrade --install kubescape kubescape/kubescape-operator \
     -n kubescape --create-namespace \
     --set operator.enabled=false  # We'll run it locally
   ```

2. **Port-forward the required services:**
   ```bash
   kubectl port-forward -n kubescape service/kubescape 8080:8080 &
   kubectl port-forward -n kubescape service/kubevuln 8081:8080 &
   ```

3. **Create configuration files** (see [Configuration Files](#configuration-files) section)

4. **Build and run:**
   ```bash
   go build -o operator .
   ./operator
   ```

---

## Configuration

### Configuration Files

The Operator reads configuration from `/etc/config/`. When running locally, set the `CONFIG` environment variable to point to your config directory.

<details>
<summary><b>/etc/config/clusterData.json</b> - Cluster connection settings</summary>

```json
{
  "gatewayWebsocketURL": "",
  "gatewayRestURL": "",
  "kubevulnURL": "127.0.0.1:8081",
  "kubescapeURL": "127.0.0.1:8080",
  "accountID": "your-account-id",
  "clusterName": "my-cluster"
}
```
</details>

<details>
<summary><b>/etc/config/config.json</b> - Operator settings</summary>

```json
{
  "namespace": "kubescape",
  "port": "4002",
  "cleanupDelay": 600000000000,
  "workerConcurrency": 3,
  "triggerSecurityFramework": false,
  "matchingRulesFilename": "/etc/config/matchingRules.json"
}
```
</details>

<details>
<summary><b>/etc/config/capabilities.json</b> - Feature toggles</summary>

```json
{
  "capabilities": {
    "configurationScan": "enable",
    "continuousScan": "disable",
    "nodeScan": "enable",
    "vulnerabilityScan": "enable",
    "relevancy": "enable",
    "networkGenerator": "disable",
    "runtimeObservability": "disable",
    "nodeSbomGeneration": "disable",
    "seccomp": "disable",
    "otel": "enable",
    "admissionController": "disable"
  },
  "components": {
    "operator": { "enabled": true },
    "kubescape": { "enabled": true },
    "kubescapeScheduler": { "enabled": true },
    "kubevuln": { "enabled": true },
    "kubevulnScheduler": { "enabled": true },
    "nodeAgent": { "enabled": true },
    "hostScanner": { "enabled": true },
    "storage": { "enabled": true },
    "otelCollector": { "enabled": true },
    "serviceDiscovery": { "enabled": true }
  },
  "configurations": {
    "persistence": "enable",
    "server": {
      "account": null,
      "discoveryUrl": "https://api.kubescape.io"
    }
  }
}
```
</details>

<details>
<summary><b>/etc/config/matchingRules.json</b> - Continuous scanning filters (optional)</summary>

```json
{
  "match": [
    {
      "apiGroups": ["apps"],
      "apiVersions": ["v1"],
      "resources": ["deployments", "daemonsets", "statefulsets"]
    },
    {
      "apiGroups": [""],
      "apiVersions": ["v1"],
      "resources": ["pods"]
    }
  ],
  "namespaces": ["default", "production"]
}
```
</details>

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CONFIG` | Path to cluster configuration file | `/etc/config/clusterData.json` |
| `SERVICES` | Path to services configuration file | `/etc/config/services.json` |
| `OTEL_COLLECTOR_SVC` | OpenTelemetry collector address (e.g., `otel-collector:4317`) | *not set* |
| `RELEASE` | Image version for logging | *set at build time* |
| `NODE_NAME` | Kubernetes node name (from downward API) | *set by Kubernetes* |

### Configuration Defaults

| Setting | Default Value | Description |
|---------|---------------|-------------|
| `namespace` | `kubescape` | Namespace for Kubescape components |
| `port` | `4002` | REST API port |
| `cleanupDelay` | `10m` | Interval for cleanup routines |
| `workerConcurrency` | `3` | Number of concurrent workers |
| `triggerSecurityFramework` | `false` | Trigger security framework on startup |
| `eventDeduplicationInterval` | `2m` | Interval to deduplicate continuous scan events |
| `podScanGuardTime` | `1h` | Minimum pod age before scanning (for orphan pods) |
| `registryScanningSkipTlsVerify` | `false` | Skip TLS verification for registry scanning |
| `registryScanningInsecure` | `false` | Allow insecure registry connections |

---

## API Documentation

The Operator provides an HTTP REST API on port `4002` (configurable).

Interactive API documentation is available at:

| UI | Endpoint |
|----|----------|
| SwaggerUI | `/openapi/v2/swaggerui` |
| RapiDoc | `/openapi/v2/rapi` |
| Redoc | `/openapi/v2/docs` |

Access via port-forward:
```bash
kubectl port-forward -n kubescape svc/operator 4002:4002
# Then open: http://localhost:4002/openapi/v2/swaggerui
```

---

## API Examples

All examples assume you have port-forwarded the Operator:
```bash
kubectl port-forward -n kubescape svc/operator 4002:4002 &
```

### Kubescape Configuration Scans

#### Trigger a Kubescape scan (all frameworks)

```bash
curl -X POST http://localhost:4002/v1/triggerAction \
  -H 'Content-Type: application/json' \
  -d '{
    "commands": [{
      "commandName": "kubescapeScan",
      "args": {
        "scanV1": {
          "submit": true
        }
      }
    }]
  }'
```

#### Trigger a scan for specific frameworks

```bash
curl -X POST http://localhost:4002/v1/triggerAction \
  -H 'Content-Type: application/json' \
  -d '{
    "commands": [{
      "commandName": "kubescapeScan",
      "args": {
        "scanV1": {
          "submit": true,
          "targetType": "framework",
          "targetNames": ["nsa", "mitre"]
        }
      }
    }]
  }'
```

#### Create a scheduled Kubescape scan (CronJob)

```bash
curl -X POST http://localhost:4002/v1/triggerAction \
  -H 'Content-Type: application/json' \
  -d '{
    "commands": [{
      "commandName": "setKubescapeCronJob",
      "args": {
        "kubescapeJobParams": {
          "cronTabSchedule": "0 0 * * *"
        },
        "scanV1": {
          "submit": true,
          "targetType": "framework",
          "targetNames": ["nsa"]
        }
      }
    }]
  }'
```

#### Update a scheduled Kubescape scan

```bash
curl -X POST http://localhost:4002/v1/triggerAction \
  -H 'Content-Type: application/json' \
  -d '{
    "commands": [{
      "commandName": "updateKubescapeCronJob",
      "args": {
        "kubescapeJobParams": {
          "cronTabSchedule": "0 6 * * *",
          "name": "kubescape-scheduler"
        }
      }
    }]
  }'
```

#### Delete a scheduled Kubescape scan

```bash
curl -X POST http://localhost:4002/v1/triggerAction \
  -H 'Content-Type: application/json' \
  -d '{
    "commands": [{
      "commandName": "deleteKubescapeCronJob",
      "args": {
        "kubescapeJobParams": {
          "name": "kubescape-scheduler"
        }
      }
    }]
  }'
```

### Vulnerability Scans

#### Trigger an image vulnerability scan

```bash
curl -X POST http://localhost:4002/v1/triggerAction \
  -H 'Content-Type: application/json' \
  -d '{
    "commands": [{
      "commandName": "scan",
      "wlid": "wlid://cluster-my-cluster/namespace-default/deployment-nginx"
    }]
  }'
```

#### Create a scheduled vulnerability scan (CronJob)

```bash
curl -X POST http://localhost:4002/v1/triggerAction \
  -H 'Content-Type: application/json' \
  -d '{
    "commands": [{
      "commandName": "setVulnScanCronJob",
      "wlid": "wlid://cluster-my-cluster/namespace-default",
      "args": {
        "jobParams": {
          "cronTabSchedule": "0 2 * * *"
        }
      }
    }]
  }'
```

#### Update a scheduled vulnerability scan

```bash
curl -X POST http://localhost:4002/v1/triggerAction \
  -H 'Content-Type: application/json' \
  -d '{
    "commands": [{
      "commandName": "updateVulnScanCronJob",
      "args": {
        "jobParams": {
          "cronTabSchedule": "0 4 * * *",
          "name": "vuln-scan-scheduled-123456789"
        }
      }
    }]
  }'
```

#### Delete a scheduled vulnerability scan

```bash
curl -X POST http://localhost:4002/v1/triggerAction \
  -H 'Content-Type: application/json' \
  -d '{
    "commands": [{
      "commandName": "deleteVulnScanCronJob",
      "args": {
        "jobParams": {
          "name": "vuln-scan-scheduled-123456789"
        }
      }
    }]
  }'
```

### Registry Scans

#### Scan a container registry

```bash
curl -X POST http://localhost:4002/v1/triggerAction \
  -H 'Content-Type: application/json' \
  -d '{
    "commands": [{
      "commandName": "scanRegistry",
      "args": {
        "registryInfo-v1": {
          "registryName": "ghcr.io/kubescape",
          "registryProvider": "ghcr.io",
          "depth": 1,
          "kind": "ghcr.io",
          "isHTTPS": true,
          "skipTLSVerify": false,
          "authMethod": {
            "type": "public"
          }
        }
      }
    }]
  }'
```

#### Create a scheduled registry scan (CronJob)

```bash
curl -X POST http://localhost:4002/v1/triggerAction \
  -H 'Content-Type: application/json' \
  -d '{
    "commands": [{
      "commandName": "setRegistryScanCronJob",
      "args": {
        "jobParams": {
          "cronTabSchedule": "0 0 * * *"
        },
        "registryInfo-v1": {
          "registryName": "ghcr.io/kubescape",
          "registryProvider": "ghcr.io",
          "depth": 1,
          "kind": "ghcr.io",
          "isHTTPS": true,
          "skipTLSVerify": false,
          "authMethod": {
            "type": "public"
          }
        }
      }
    }]
  }'
```

---

## Private Registry Authentication

To scan images from private container registries, create a Kubernetes Secret with your credentials.

### Step 1: Create base64-encoded credentials

```bash
echo -n 'registry.example.com' | base64
# Output: cmVnaXN0cnkuZXhhbXBsZS5jb20=

echo -n 'myusername' | base64
# Output: bXl1c2VybmFtZQ==

echo -n 'mypassword' | base64
# Output: bXlwYXNzd29yZA==
```

### Step 2: Create the Secret

Create a file named `registry-secret.yaml`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-registry-credentials
  namespace: kubescape
  labels:
    kubescape.io/registry: creds
type: Opaque
data:
  registry: cmVnaXN0cnkuZXhhbXBsZS5jb20=   # registry.example.com
  username: bXl1c2VybmFtZQ==                # myusername
  password: bXlwYXNzd29yZA==                # mypassword
```

Apply the secret:

```bash
kubectl apply -f registry-secret.yaml
```

### Step 3: Automatic Discovery

Kubescape automatically discovers secrets with the label `kubescape.io/registry=creds` in the `kubescape` namespace and uses them for registry authentication during image scans.

> **Note:** The `registry` field should contain the registry hostname without the `http://` or `https://` prefix.

---

## Features

### Continuous Scanning

When enabled, the Operator watches for changes to Kubernetes resources and automatically triggers rescans when configurations change.

**Enable via Helm:**
```bash
helm upgrade kubescape kubescape/kubescape-operator \
  -n kubescape \
  --set capabilities.continuousScan=enable
```

**Configure matching rules** to specify which resources to watch:
```json
{
  "match": [
    {
      "apiGroups": ["apps"],
      "apiVersions": ["v1"],
      "resources": ["deployments"]
    }
  ],
  "namespaces": ["default", "production"]
}
```

### Admission Controller

The admission controller validates workloads against security policies before they are admitted to the cluster.

**Enable via Helm:**
```bash
helm upgrade kubescape kubescape/kubescape-operator \
  -n kubescape \
  --set capabilities.admissionController=enable
```

When enabled, the Operator runs an HTTPS webhook server on port `8443` that integrates with Kubernetes admission control.

---

## Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/kubescape/operator.git
cd operator

# Build
go build -o operator .

# Build for Linux (cross-compile)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o operator .

# Build Docker image
make docker-build TAG=dev
```

### VS Code Configuration

<details>
<summary><b>.vscode/launch.json</b></summary>

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch Operator",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "${workspaceRoot}",
      "env": {
        "CONFIG": "${workspaceRoot}/.vscode/clusterData.json"
      },
      "args": ["-alsologtostderr", "-v=4"]
    }
  ]
}
```
</details>

<details>
<summary><b>.vscode/clusterData.json</b></summary>

```json
{
  "kubevulnURL": "127.0.0.1:8081",
  "kubescapeURL": "127.0.0.1:8080",
  "accountID": "",
  "clusterName": "dev-cluster"
}
```
</details>

**Remember to port-forward the required services:**
```bash
kubectl port-forward -n kubescape service/kubescape 8080:8080 &
kubectl port-forward -n kubescape service/kubevuln 8081:8080 &
```

### Generating Swagger Documentation

```bash
go generate ./...
```

This updates `docs/swagger.yaml` with the latest API specification.

---

## Troubleshooting

### Common Issues

#### Operator pod is not starting

Check the pod logs:
```bash
kubectl logs -n kubescape -l app.kubernetes.io/name=operator
```

Common causes:
- Missing ConfigMaps (`kubescape-config`, `kubescape-capabilities`)
- Unable to connect to Kubernetes API server
- Invalid configuration files

#### Scans are not being triggered

1. Verify the Operator is running:
   ```bash
   kubectl get pods -n kubescape -l app.kubernetes.io/name=operator
   ```

2. Check that Kubescape/Kubevuln services are accessible:
   ```bash
   kubectl get svc -n kubescape
   ```

3. Check Operator logs for errors:
   ```bash
   kubectl logs -n kubescape -l app.kubernetes.io/name=operator --tail=100
   ```

#### REST API returns errors

1. Ensure you're using the correct port (default: 4002)
2. Verify the request body matches the expected schema (see [API Documentation](#api-documentation))
3. Check that the target components (Kubescape, Kubevuln) are enabled in capabilities

#### Continuous scanning not working

1. Verify continuous scanning is enabled:
   ```bash
   kubectl get configmap -n kubescape kubescape-capabilities -o yaml | grep continuousScan
   ```

2. Check that `matchingRules.json` is properly configured

3. Verify the watched namespaces contain the expected resources

### Debug Mode

Enable debug logging by setting the log level:
```bash
kubectl set env deployment/operator -n kubescape LOG_LEVEL=debug
```

When debug mode is enabled, a pprof server starts on port `6060` for profiling.

### Getting Help

- 📖 [Kubescape Documentation](https://kubescape.io/docs/)
- 💬 [Slack Community](https://cloud-native.slack.com/archives/C04EY3ZF9GE)
- 🐛 [GitHub Issues](https://github.com/kubescape/operator/issues)

---

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](https://github.com/kubescape/project-governance/blob/main/CONTRIBUTING.md) for details.

- [Code of Conduct](https://github.com/kubescape/project-governance/blob/main/CODE_OF_CONDUCT.md)
- [Governance](https://github.com/kubescape/project-governance/blob/main/GOVERNANCE.md)
- [Security Policy](https://github.com/kubescape/project-governance/blob/main/SECURITY.md)

---

## License

Copyright 2021-2024 Kubescape Authors

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.