# Admission webhook client authentication (opt-in mutual TLS)

The operator's validating admission webhook (`/validate`, port `8443`) serves
HTTPS with a server certificate so that the Kubernetes API server can verify the
webhook. By default it does **not** authenticate the *caller*: any client that
can reach the port can send an `AdmissionReview`, and the webhook builds its
evaluation attributes from caller-supplied `UserInfo`, `Object` and `OldObject`.

Because the webhook is **audit-only** — it always responds `Allowed: true` and
its `ValidatingWebhookConfiguration` uses `failurePolicy: Ignore` — this cannot
change a Kubernetes admission decision. The residual concern is integrity of
admission *telemetry* when a real alert exporter is configured: a reachable,
unauthenticated caller could submit fabricated reviews.

This feature lets an operator require **mutual TLS**: the webhook then accepts a
request only from a peer presenting a client certificate that chains to a
configured CA.

## Trust model

- **What is authenticated:** the TLS transport peer. A caller must present a
  client certificate signed by the configured client CA. This is a
  cryptographic check on the connection, independent of the request body.
- **What is *not* trusted as identity:** `UserInfo`, `Object`, `OldObject` and
  the other `AdmissionReview` fields remain untrusted input used only for rule
  attribution — never as proof of who the caller is. Client authentication is
  the only caller-identity check; the body cannot grant it.
- **Scope:** this authenticates the API server to the webhook. It does not
  change admission semantics, rule evaluation, or the `Allowed: true` response.

## Why it is opt-in (and cannot be the default)

The API server presents a client certificate to a webhook **only** when the
cluster administrator configures the control plane's
`--admission-control-config-file` with an `AdmissionConfiguration` that supplies
a `kubeConfigFile` for the webhook host. For example:

```yaml
# admission-control-config.yaml (referenced by kube-apiserver --admission-control-config-file)
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: ValidatingAdmissionWebhook
    configuration:
      apiVersion: apiserver.config.k8s.io/v1
      kind: WebhookAdmissionConfiguration
      kubeConfigFile: /etc/kubernetes/admission/webhook-kubeconfig.yaml
```

```yaml
# webhook-kubeconfig.yaml — client cert the API server presents to webhooks
apiVersion: v1
kind: Config
users:
  - name: '*'            # or the exact webhook service DNS name
    user:
      client-certificate: /etc/kubernetes/admission/apiserver-client.crt
      client-key: /etc/kubernetes/admission/apiserver-client.key
```

A Helm chart cannot set a control-plane flag, and several managed control planes
(EKS/GKE/AKS) do not expose it. Enabling enforced mTLS by default would make the
API server unable to call the webhook in those environments. Admission would
still *succeed* (`failurePolicy: Ignore`), but **admission telemetry would stop**
— a silent loss of security signal. So the webhook defaults to server-TLS-only
and this is enabled deliberately, together with the server-side configuration.

## Enabling it

1. **Provision a client CA** and issue the API server a client certificate from
   it (the `apiserver-client.crt/key` above). Keep the CA certificate.

2. **Configure the control plane** as shown above so the API server presents
   that client certificate to the webhook.

3. **Create a secret** in the Kubescape namespace holding the CA certificate the
   webhook should trust:

   ```bash
   kubectl -n kubescape create secret generic apiserver-webhook-client-ca \
     --from-file=ca.crt=/path/to/client-ca.crt
   ```

4. **Enable the feature** in the chart:

   ```yaml
   capabilities:
     admissionController: enable
   operator:
     admissionWebhooks:
       clientAuth:
         enabled: true
         secretName: apiserver-webhook-client-ca
         caKey: ca.crt          # key within the secret
   ```

   This mounts the CA at `/etc/admission-client-ca/ca.crt` and sets
   `ADMISSION_CLIENT_CA_FILE` on the operator. The chart refuses to render
   `clientAuth.enabled: true` without a `secretName`.

The operator reads `ADMISSION_CLIENT_CA_FILE` directly; the env var is the only
contract, so the mechanism also works outside Helm.

## Scope of the TLS listener

When mTLS is enabled it applies to the **entire webhook TLS listener** (port `8443`), not just
`/validate`. Both `/validate` **and** `/health` on that listener then require a client certificate
that chains to the configured CA; an unauthenticated caller is rejected at the TLS handshake for
either path.

- The operator's own **readiness and liveness probes are unaffected**: they target the separate
  readiness endpoint on port `8000` (`/v1/readiness`, `/v1/liveness`), which has no TLS and no
  client-certificate requirement. Enabling mTLS does not change pod health checking.
- **External monitoring that scrapes the webhook `/health` on `8443` must present a trusted client
  certificate** once mTLS is enabled, or switch to probing the port `8000` readiness endpoint
  instead. This is the one caller-visible behaviour change beyond `/validate`.

## Behaviour and guarantees

- **Fail-closed on misconfiguration.** If client auth is enabled but the CA file
  is missing or contains no certificate, the webhook server returns a startup
  error instead of serving unauthenticated. There is no silent downgrade.
- **Rotation without restart.** The trusted CA bundle is re-read per TLS
  handshake. Replacing the secret (Kubernetes swaps the `..data` symlink) is
  picked up on the next connection. A half-written/invalid CA file keeps the
  last good trust pool rather than dropping verification.
- **No weakening of server TLS.** The existing server-certificate callback and
  its rotation are unchanged; client verification is layered on top.
- **Disabled is unchanged.** With `clientAuth.enabled: false` (default) the
  rendered manifests and the server's TLS behaviour are identical to before.

## Staged migration

1. Roll out the client CA secret and the control-plane configuration first,
   while `clientAuth.enabled: false`. Confirm the API server now presents a
   client certificate (the webhook still accepts everyone at this stage).
2. Flip `clientAuth.enabled: true`. Verify admission alerts/telemetry continue
   for legitimate workloads (confirming the API server's cert is trusted).
3. If telemetry stops, the API-server client certificate is not trusted by the
   configured CA — fix the CA/kubeconfig and re-check; the webhook itself
   fails closed, so it will not revert to unauthenticated.

## Compatibility limitations

- Requires control-plane access to set `--admission-control-config-file`. Not
  available on control planes that do not expose it; on those, this feature
  cannot be used and the webhook stays server-TLS-only.
- Authenticates only the transport peer (the API server). It does not
  distinguish *which* API server identity beyond "signed by the configured CA";
  scope the client CA accordingly.
- It does not alter `failurePolicy: Ignore` or the `Allowed: true` response, so
  it changes neither admission outcomes nor rule evaluation — only who may
  submit reviews.
