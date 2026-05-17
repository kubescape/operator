# kube-init-certgen

Minimal init-container image for generating TLS certificates and patching Kubernetes resources with the resulting CA bundle. Designed as a replacement for hook-based cert generators (e.g. `kube-webhook-certgen`).

Image: `quay.io/kubescape/kube-init-certgen`

## Used by

- [kubescape/operator](https://github.com/kubescape/operator) — admission webhook (`ValidatingWebhookConfiguration`) cert lifecycle
- [kubescape/storage](https://github.com/kubescape/storage) — aggregated API (`APIService`) cert lifecycle

## How it works

Two scripts run as sequential init containers on the target workload:

1. **`certgen-create.sh`** — generates a CA + leaf certificate (ECDSA P-256) and stores them in a Kubernetes Secret. Idempotent: if the Secret already exists, it reuses the existing cert without regenerating.
2. **`certgen-patch.sh`** — reads the CA from the Secret and patches its `caBundle` field into either a `ValidatingWebhookConfiguration` or an `APIService`. Retries until the resource is available.

Because both scripts run as init containers, the main container only starts after certs are ready and the caBundle is patched — ArgoCD's health check naturally waits on this.

## Image contents

Base: `alpine/k8s:1.36.1` (includes `kubectl`, `jq`, `bash`)
Added: `openssl` (via `apk`)

## Scripts

### certgen-create.sh

```
--namespace      <ns>        Namespace for the secret (required)
--secret-name    <name>      Name of the secret to read/create (required)
--host           <hosts>     Comma-separated DNS SANs for the leaf cert (required)
--out-dir        <path>      Directory to write cert/key into (required)
--ca-name        <key>       Secret key for the CA cert (default: ca)
--cert-name      <key>       Secret key for the leaf cert (default: cert)
--key-name       <key>       Secret key for the leaf key (default: key)
--days           <n>         Certificate validity in days (default: 36500)
```

### certgen-patch.sh

```
--namespace      <ns>        Namespace of the secret (required)
--secret-name    <name>      Name of the secret holding the CA (required)
--resource-type  vwc|apiservice  Resource type to patch (required)
--resource-name  <name>      Name of the resource to patch (required)
--ca-name        <key>       Secret key for the CA cert (default: ca)
--retries        <n>         Max patch attempts (default: 60)
--retry-interval <s>         Seconds between attempts (default: 5)
```

## Building

```sh
docker buildx build --platform linux/amd64,linux/arm64 -t quay.io/kubescape/kube-init-certgen:latest --push .
```
