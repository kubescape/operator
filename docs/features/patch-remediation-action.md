# Generic patch remediation action

## Overview

`TypeOperatorAction` ("operatorAction") gained a `patch` action alongside
`annotate`, `quarantine`, and `revert`. It lets the backend apply a targeted
Strategic Merge Patch or JSON Merge Patch (e.g. injecting
`securityContext.seccompProfile`) to a workload without knowing — or sending —
the workload's full YAML.

Implementation: `mainhandler/remediators/patch.go` (`PatchRemediator`),
dispatched from `mainhandler/actionhandler.go`'s `handleActionOnTarget`, and
registered in `remediators.NewRegistry`.

## Command shape

`Command.Args` for `action: "patch"`:

- `target` — as for every other action (`kind`, `namespace`, `name`); one of
  `Deployment`, `StatefulSet`, `DaemonSet`, `Pod`.
- `patch` (required) — a JSON or YAML object, as a string or a raw JSON value.
  Must be object-shaped: RFC 6902 JSON Patch arrays are not supported.
- `patchType` (optional) — `"strategic"` (default) or `"merge"`.
- `dryRun` — same safe-by-default semantics as every other action: omitted or
  `true` means a server-side dry-run; only an explicit `false` writes.

`patch`/`patchType` are typed fields on `apis.OperatorActionArgs` as of
armoapi-go `v0.0.761` (`Patch apis.OperatorActionPatchBody`, `PatchType
string`). `OperatorActionPatchBody.UnmarshalJSON` accepts either a JSON
string or a raw JSON object on the wire, matching what this action has
always tolerated.

## Safety rails

Same generic rails as every action, enforced in `handleActionOnTarget` before
dispatch: dry-run-by-default, the target namespace must not be in
`SkipNamespace`, and a namespaced kind requires a namespace.

Patch-specific hardening, enforced in both `Plan` and `Apply` (so a
hand-constructed `Plan` cannot skip it):

- **Size cap** — patch body limited to 256 KiB.
- **Shape validation** — must decode to a non-empty JSON/YAML object; `null`,
  empty objects (`{}`), and JSON Patch arrays are rejected.
- **Escalation denylist** — a patch may not touch: `hostNetwork`, `hostPID`,
  `hostIPC`, `serviceAccountName`/`serviceAccount`, `volumes`, `nodeName`,
  `metadata.ownerReferences`, `metadata.finalizers`, a container's
  `securityContext.privileged`/`allowPrivilegeEscalation`/
  `capabilities.add`, or a container's `image`. This is defense-in-depth
  against a patch escalating from "fix a workload's config" to node or
  cluster compromise.

## Revert

Arbitrary patches carry no recorded pre-state, so `PatchRemediator.Revert`
always returns an error and is deliberately **not** included in
`revertTarget`'s `reversible` list (including it would abort revert for every
target, not just patched ones). When a `revert` action runs against a target
that may have been patched, the recorded result/audit event explicitly notes
that any prior patch was **not** reverted.

## Audit trail

A confirmed (`dryRun: false`) patch's body and patch type are recorded on
`remediators.Result` (`Patch`/`PatchType` fields), which flows into both the
`OperatorCommand` status payload and the `KubescapeRemediation` Kubernetes
event — so an applied change can be reconstructed after the fact.

## patch is only deliverable via the OperatorCommand CRD path

Every other `operatorAction` (`annotate`, `quarantine`, `revert`, and
`cordon` once implemented) is reachable via **two** ingress points that both
funnel into the same `handleRequest`/`handleOperatorAction` dispatch:

1. The `OperatorCommand` CRD, watched by `watcher/commandshandler.go`. In the
   commercial/connected deployment this is written by the `synchronizer`
   component, whose own K8s ServiceAccount and `ClusterRole` are the actual
   authorization boundary — reachable only through synchronizer's own
   authenticated connection to the backend. In the standalone/GitOps case a
   user or CI pipeline `kubectl apply`s the CR directly, authorized by their
   own RBAC on that resource.
2. The `/v1/triggerAction` HTTP endpoint (`restapihandler/triggeraction.go`).
   This is the **documented, intended transport** for the `kubescape` CLI's
   `operator remediate annotate|quarantine|revert` subcommand (see
   [`designs-and-proposals/cli-cluster-operations.md`](https://github.com/kubescape/designs-and-proposals/blob/main/proposals/cli-cluster-operations.md)),
   which reaches it via `kubectl port-forward` — itself RBAC-gated (`pods/portforward`
   create permission on the operator's namespace). However, the endpoint
   itself has **no application-level caller authentication**, and its
   `Service` carries no `NetworkPolicy`: any pod on the cluster network can
   reach `operator:4002/v1/triggerAction` directly, bypassing the
   port-forward/RBAC boundary the CLI relies on entirely (verified live —
   see [operator#411](https://github.com/kubescape/operator/pull/411),
   closed in favor of this narrower fix once it was clear the endpoint's
   `operatorAction` dispatch is itself a required, documented feature, not
   an oversight).

`patch` was **not** part of that design (the design's action set is
`annotate`/`quarantine`/`cordon`/`revert`) and has no CLI subcommand or other
legitimate use of the `/v1/triggerAction` transport. So rather than closing
the endpoint's general reachability gap (a NetworkPolicy-level fix, tracked
separately against `kubescape/helm-charts`, since `kubectl port-forward`
traffic never crosses the pod network a `NetworkPolicy` governs and so isn't
blocked by one), `handleOperatorAction` rejects `patch` outright unless
`sessionObj.ParentCommandDetails` is set — the signal, already used
elsewhere in this codebase, that a command was delivered via the CRD watcher
rather than `/v1/triggerAction`. This keeps every design-documented action
working exactly as before while giving `patch` — the one action with no
legitimate use for the unauthenticated HTTP path — the RBAC-backed CRD path
as its only way in.
