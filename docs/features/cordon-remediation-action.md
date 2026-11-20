# Cordon remediation action

## Overview

`TypeOperatorAction` ("operatorAction") supports the `cordon` action alongside
`annotate`, `quarantine`, `patch`, and `revert`. It allows an administrator or
incident response pipeline to mark a Kubernetes Node as unschedulable
(`spec.unschedulable: true`), preventing new pods from landing on a node that
exhibits security findings, Indicators of Compromise (IoCs), or vulnerabilities.

Implementation: `mainhandler/remediators/cordon.go` (`CordonRemediator`),
dispatched from `mainhandler/actionhandler.go`'s `handleActionOnTarget`, and
registered in `remediators.NewRegistry`.

## Command shape

`Command.Args` for `action: "cordon"`:

- `target` (required) — explicit cluster target: `kind: "Node"`, `name: "<node-name>"`.
  Nodes are cluster-scoped, so `namespace` is omitted or ignored.
- `reason` (optional) — audit reason recorded on the node annotations (e.g. `ioc-detected`).
- `findingRef` (optional) — reference to the alerting finding or security incident.
- `dryRun` — same safe-by-default semantics as every other action: omitted or
  `true` means a server-side dry-run; only an explicit `false` writes.

`cordon` acts on explicit Node targets only. Findings-driven selector targeting
(which queries workload configuration findings) is not supported for `cordon`
and returns an informative error.

## Semantics & Safety Rails

- **Target Kind**: Must be `Node` (case-insensitive). Target kinds other than
  `Node` (such as `Deployment` or `Pod`) are rejected.
- **Dry-run by default**: Commands without `--confirm` (`dryRun: false`) issue a
  Kubernetes server-side dry-run (`metav1.DryRunAll`), validating admission and
  generating the exact plan without persisting changes.
- **Idempotency**: Applying `cordon` to a node that is already unschedulable
  succeeds cleanly and notes this in the plan and execution description.
- **Forensic Non-destruction**: Unlike node draining, cordoning does not evict
  or terminate running containers on the node, preserving in-memory process
  trees and forensic state for security analysis.

## Revert (Uncordon)

A `revert` action targeted at a `Node` restores `spec.unschedulable = false`
and clears the Kubescape cordon annotations (`kubescape.io/cordon`,
`kubescape.io/remediated`, `kubescape.io/remediation-reason`, and
`kubescape.io/remediation-finding-ref`).

## Audit trail

A confirmed (`dryRun: false`) cordon action sets audit annotations on the node
and emits a Kubernetes Event (`Reason: KubescapeRemediation`) in the operator
namespace referencing the cordoned node.

