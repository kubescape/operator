# triggerAction command allowlist

## Overview

`/v1/triggerAction` (`restapihandler/triggeraction.go`, port `4002`, named
`trigger-port`) is an unauthenticated HTTP endpoint: it has no caller
identity check, and its Service has no NetworkPolicy restricting who can
reach it. It now only dispatches an explicit allowlist of `CommandName`
values instead of every command the operator recognizes.

## Why

The endpoint's only legitimate callers are the operator's own
scan-scheduling CronJobs, run in-cluster with a fixed, hardcoded request
body:

| CronJob | `commandName` sent |
|---|---|
| `kubescape-scheduler` | `kubescapeScan` (`apis.TypeRunKubescape`) |
| `kubevuln-scheduler` | `scan` (`apis.TypeScanImages`) |
| registry-scan CronJob (created dynamically when registry scanning is configured — see `watcher/registryhandler.go`) | `scanRegistryV2` (`apis.TypeScanRegistryV2`) |

Before this change, the endpoint's shared dispatcher (`handleRequest` in
`mainhandler/handlerequests.go`) accepted every `CommandName` it recognizes,
including `operatorAction` — the command type that drives remediation
(`annotate`/`quarantine`/`revert`/`patch`). Because nothing gates who can
reach port 4002, any pod on the cluster network could send an `operatorAction`
command and have the operator apply it with its own cluster-wide remediation
RBAC — a materially different risk than the legitimate callers' fixed,
read-only-triggering payloads.

This is a stopgap: the real fix is to stop using an unauthenticated HTTP
callback for this at all, and have these CronJobs create `OperatorCommand`
custom resources directly instead (the same, RBAC-gated mechanism the
`synchronizer` component already uses for backend-originated commands). That
migration is tracked separately since it requires Helm chart changes.

## What changed

`restapihandler/triggeraction.go` now checks each command's `CommandName`
against `triggerActionAllowedCommands` before dispatching it to the worker
pool. A command whose name isn't in that set is rejected the same way an
empty `CommandName` already was: logged, recorded as an error on its
`OperatorCommand` status (a no-op for a command that didn't originate from a
CRD, which is always true here), and skipped — it never reaches
`handleRequest`. The HTTP response is unaffected (`200`/`ok`), matching the
endpoint's existing behavior for other per-command validation failures; the
allowlist rejects the *dispatch*, not the HTTP request.

`apis.TypeOperatorAction` is deliberately excluded, so `operatorAction`
(and therefore `patch` — see `docs/features/patch-remediation-action.md`)
can only ever be dispatched via the RBAC-gated `OperatorCommand` CRD path.
