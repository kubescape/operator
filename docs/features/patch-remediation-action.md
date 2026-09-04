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

`patch`/`patchType` are not yet part of armoapi-go's typed
`OperatorActionArgs` schema, so they are read directly off the raw
`Command.Args` map (see `extractPatchArgs` in `actionhandler.go`) rather than
the parsed struct used for the other fields.

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

## Known gap: endpoint authorization

`patch` is dispatched the same way as every other `operatorAction`, including
via the operator's `/v1/triggerAction` HTTP endpoint
(`restapihandler/triggeraction.go`), which currently has **no
authentication or authorization** in front of it. That gap predates this
action, but `patch` raises its stakes materially: previously a caller
reaching that endpoint could only trigger hardcoded, low-blast-radius writes
(an annotation key, a deny-all NetworkPolicy). With `patch`, the same
unauthenticated reachability lets a caller direct the operator's cluster-wide
patch RBAC at arbitrary (denylist-permitting) workload fields.

**Authenticating and authorizing `/v1/triggerAction`** (e.g. via
`TokenReview` + `SubjectAccessReview` per caller) should be treated as a
prerequisite before enabling this action in any environment where that
endpoint is reachable by untrusted callers. This is tracked as a follow-up,
not addressed by this change.
