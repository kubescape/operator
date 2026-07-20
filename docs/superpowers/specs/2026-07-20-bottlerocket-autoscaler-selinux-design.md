# Auto-detect AWS Bottlerocket and set `super_t` SELinux type in the node-agent autoscaler

**Date:** 2026-07-20
**Status:** Approved (design)
**Repos affected:** `operator` (primary), `helm-charts`

## Problem

Customers installing Kubescape/Armo on AWS Bottlerocket nodes must manually add
`--set nodeAgent.seLinuxType=super_t` to their Helm command. Bottlerocket enforces a
strict SELinux policy; under the default container type `spc_t` the eBPF node-agent does
not get the capabilities it needs (SYS_ADMIN/SYS_PTRACE/BPF…) and crash-loops. The more
privileged `super_t` domain fixes it. Ref: https://github.com/bottlerocket-os/bottlerocket/issues/3677

This manual flag is easy to miss and complicates installation. We want the operator to
detect Bottlerocket nodes at runtime and apply the flag automatically.

## Goal

When the node-agent autoscaler is enabled (`nodeAgent.autoscaler.enabled=true`), the
operator detects Bottlerocket nodes **per node-group** and renders that group's node-agent
DaemonSet with `seLinuxOptions.type: super_t` automatically — no customer action required.

## Scope

- **In scope:** the autoscaler install path only. The operator already renders one
  node-agent DaemonSet per node-group at runtime, so detection slots in with no new
  apply mechanism.
- **Out of scope:** the standard single-DaemonSet install and `multipleDaemonSets` mode
  (no runtime renderer). Those keep using the manual `nodeAgent.seLinuxType` value and are
  left unchanged.

## Design

The implementation mirrors exactly how the autoscaler already computes CPU/memory requests,
limits, and `GOMEMLIMIT`: the operator computes a per-group value and injects it through
`TemplateData`; the Helm template exposes a Go-template placeholder that the operator
renders at runtime.

### 1. Detection — `nodeagentautoscaler/nodegrouper.go`

- Add `HasBottlerocket bool` to the `NodeGroup` struct.
- In `GetNodeGroups`, while iterating a group's ready nodes, detect Bottlerocket via a
  **case-insensitive substring match** on the node's OS image string:

  ```go
  isBottlerocket := strings.Contains(strings.ToLower(node.Status.NodeInfo.OSImage), "bottlerocket")
  ```

  Bottlerocket reports `OSImage` like `"Bottlerocket OS 1.19.2 (aws-k8s-1.29)"`. A
  substring match is version-independent and robust to formatting changes.
- Set `HasBottlerocket = true` if **any** ready node in the group is Bottlerocket
  ("per-group any-Bottlerocket" flag). This must be OR-ed across nodes in **both** the
  new-group branch and the existing-group branch of the grouping loop.
- Gate the whole check on the opt-out toggle: when
  `config.NodeAgentAutoscaler.BottlerocketAutoDetect == false`, never set the flag
  (leaving every group on the default SELinux type).

### 2. Value selection — `nodeagentautoscaler/templaterenderer.go`

- Add `SELinuxType string` to `TemplateData`.
- Add the default SELinux type to `TemplateRenderer` (constructor parameter, mirroring
  `goMemLimitPercentage`): `NewTemplateRenderer(templatePath, goMemLimitPercentage, nodeGroupLabelKey, defaultSELinuxType)`.
- In `RenderDaemonSet`, compute:

  ```go
  seLinuxType := tr.defaultSELinuxType // e.g. "spc_t"
  if group.HasBottlerocket {
      seLinuxType = "super_t"
  }
  ```

  and set `data.SELinuxType = seLinuxType`. `"super_t"` is a constant in the operator.

### 3. Template — `helm-charts/.../templates/node-agent/_node-agent.tpl`

Make the `seLinuxOptions` block `autoscalerMode`-aware, exactly like `node-agent.resources`
and the `GOMEMLIMIT` env block. Current (line ~229-230):

```yaml
    seLinuxOptions:
      type: {{ .Values.nodeAgent.seLinuxType }}
```

Becomes:

```yaml
    seLinuxOptions:
      type: {{ if .autoscalerMode }}"{{`{{ .SELinuxType }}`}}"{{ else }}{{ .Values.nodeAgent.seLinuxType }}{{ end }}
```

In autoscaler mode Helm emits the literal placeholder `{{ .SELinuxType }}`, which the
operator renders per group at runtime. In standard / `multipleDaemonSets` mode the
helm-baked `.Values.nodeAgent.seLinuxType` value is emitted as today. (Confirm the
`autoscalerMode` flag is in scope at the point the container security context is defined,
as it already is for `node-agent.resources`/`node-agent.env`.)

### 4. Config plumbing — mirrors `goMemLimitPercentage`

**Operator (`config/config.go`):**
- Add to `NodeAgentAutoscalerConfig`:
  - `SELinuxType string` (json `seLinuxType`) — default/non-Bottlerocket value.
  - `BottlerocketAutoDetect bool` (json `bottlerocketAutoDetect`) — opt-out toggle.
- Add viper defaults:
  - `nodeAgentAutoscaler.seLinuxType` = `"spc_t"`
  - `nodeAgentAutoscaler.bottlerocketAutoDetect` = `true`

**Operator (`main.go`):** pass `cfg.SELinuxType` into `NewTemplateRenderer`. `NodeGrouper`
already receives the full `NodeAgentAutoscalerConfig`, so it reads `BottlerocketAutoDetect`
directly — no signature change there.

**Chart (`helm-charts/.../templates/operator/configmap.yaml`, `config.json`):** add both
fields under the `nodeAgentAutoscaler` block:
- `seLinuxType` wired from `.Values.nodeAgent.seLinuxType` (existing value, default `spc_t`).
- `bottlerocketAutoDetect` wired from a new `.Values.nodeAgent.autoscaler.bottlerocketAutoDetect`.

**Chart (`values.yaml`):** add `nodeAgent.autoscaler.bottlerocketAutoDetect: true` with a
comment explaining it auto-sets `super_t` on detected Bottlerocket node-groups.

## Behavior & edge cases

- **Reconcile logic unchanged.** The rendered DaemonSet simply carries the correct SELinux
  type. On node/OS churn, the next reconcile (≤ `reconcileInterval`, default 5m) re-renders
  and `Update()` applies the change — self-healing.
- **Mixed group.** If an instance-type group mixes Bottlerocket and non-Bottlerocket nodes,
  the whole group's DaemonSet gets `super_t`. The non-Bottlerocket nodes end up more
  privileged than strictly necessary — accepted as harmless (decision: per-group flag over
  splitting the group by OS).
- **Unknown / empty `OSImage`.** Treated as non-Bottlerocket → keeps the default type. Safe.
- **Toggle off.** Identical to today's behavior (every group uses the default SELinux type).
- **Non-autoscaler installs.** Completely unchanged; they continue to honor
  `nodeAgent.seLinuxType`.

## Testing

- **Unit (operator):**
  - `nodegrouper`: group containing a Bottlerocket node → `HasBottlerocket == true`; mixed
    group → true; case variations in `OSImage` (e.g. `"bottlerocket"`, `"Bottlerocket OS"`)
    → true; non-Bottlerocket → false; toggle off → always false.
  - `templaterenderer`: `HasBottlerocket == true` → rendered type `super_t`;
    `HasBottlerocket == false` → configured default (`spc_t`); custom default respected.
- **Integration (operator):** extend the existing autoscaler test that extracts the
  DaemonSet template from Helm — assert `super_t` renders for a Bottlerocket group and the
  default renders for a non-Bottlerocket group.
- **Helm:** assert autoscaler mode emits the `{{ .SELinuxType }}` placeholder, while
  standard and `multipleDaemonSets` modes still emit `.Values.nodeAgent.seLinuxType`.

## Files touched

**operator:** `nodeagentautoscaler/nodegrouper.go`, `nodeagentautoscaler/templaterenderer.go`,
`config/config.go`, `main.go`, corresponding `_test.go` files,
`docs/node-agent-autoscaler.md`.

**helm-charts:** `charts/kubescape-operator/templates/node-agent/_node-agent.tpl`,
`charts/kubescape-operator/templates/operator/configmap.yaml`,
`charts/kubescape-operator/values.yaml`, chart README.

**customer docs (follow-up):** note in
`readme-armo-hub-docs/docs/Installation/kubernetes/installation-troubleshooting.md` that the
flag is auto-handled when the autoscaler is enabled.

## Cross-repo coordination

The operator and chart changes must ship together: the operator expects the template to
contain the `{{ .SELinuxType }}` placeholder (autoscaler mode), and the chart expects the
operator to render it. An operator running against an old template (no placeholder) simply
renders the helm-baked value — safe fallback, no crash. A new template rendered by an old
operator would leave the literal `{{ .SELinuxType }}` string — so the chart bump must not
land in customers' clusters ahead of the matching operator image.
