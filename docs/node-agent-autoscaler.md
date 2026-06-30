# Node Agent Autoscaler

## Overview

The Node Agent Autoscaler is an operator component that dynamically creates and manages `node-agent` DaemonSets based on node group characteristics in the cluster. It automatically calculates resource requests/limits as a percentage of each node group's allocatable resources, ensuring optimal resource utilization across heterogeneous clusters.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Autoscaler                                     │
│  ┌──────────────────┐   ┌────────────────────┐   ┌──────────────────┐   │
│  │   NodeGrouper    │──▶│  TemplateRenderer  │──▶│  DaemonSet CRUD  │   │
│  │                  │   │                    │   │                  │   │
│  │ • List nodes     │   │ • Load template    │   │ • Create/Update  │   │
│  │ • Group by label │   │ • Watch for reload │   │ • Delete orphans │   │
│  │ • Calc resources │   │ • Render YAML      │   │ • Record events  │   │
│  └──────────────────┘   └────────────────────┘   └──────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Package Structure

```
nodeagentautoscaler/
├── autoscaler.go           # Main reconciliation loop and DaemonSet management
├── autoscaler_test.go      # Unit tests for autoscaler
├── nodegrouper.go          # Node discovery, grouping, and resource calculation
├── templaterenderer.go     # Template loading, rendering, and file watching
├── templaterenderer_test.go
└── integration_test.go     # Integration tests with Helm-generated templates
```

## Components

### Autoscaler (`autoscaler.go`)

The main orchestrator that runs the reconciliation loop.

**Key Responsibilities:**
- Initialize and coordinate other components
- Run periodic reconciliation (default: every 5 minutes)
- Manage DaemonSet lifecycle (create, update, delete)
- Set owner references for garbage collection
- Emit Kubernetes events for observability

**Reconciliation Flow:**

```go
func (a *Autoscaler) Reconcile(ctx context.Context) error {
    // 1. Get current node groups from cluster
    nodeGroups, _ := a.nodeGrouper.GetNodeGroups(ctx)

    // 2. Get existing managed DaemonSets
    existingDaemonSets, _ := a.getManagedDaemonSets(ctx)

    // 3. For each node group: calculate resources, render, create/update
    for _, group := range nodeGroups {
        resources, _ := a.nodeGrouper.CalculateResources(group)
        desiredDS, _ := a.templateRenderer.RenderDaemonSet(group, resources)
        // ... create or update DaemonSet
    }

    // 4. Delete orphaned DaemonSets (node groups that no longer exist)
    // ...
}
```

**Labels and Annotations:**

All managed DaemonSets are tagged with:

```yaml
labels:
  kubescape.io/managed-by: operator-autoscaler   # Identifies autoscaler ownership
  kubescape.io/node-group: <label-value>          # The node group this targets
annotations:
  argocd.argoproj.io/compare-options: IgnoreExtraneous  # GitOps compatibility
  argocd.argoproj.io/sync-options: Prune=false
```

**Node Targeting:**

Each DaemonSet selects the nodes it runs on based on the grouping label:

- **Normal groups** use a `nodeSelector` matching the grouping label value, e.g.
  `node.kubernetes.io/instance-type: m5.large`.
- **The default group** (`IsDefaultGroup`) targets nodes that are *missing* the
  grouping label. A `nodeSelector` cannot match an absent label, so its template
  branch instead uses a `DoesNotExist` node affinity:

  ```yaml
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: <NodeGroupLabelKey>   # the configured grouping label key
            operator: DoesNotExist
  ```

  This ensures a `node-agent` is deployed on label-less nodes (on-prem / custom
  clusters) without requiring the cluster operator to label nodes manually. The
  branch is driven by `IsDefaultGroup` in the template data; the DaemonSet
  template must therefore include both branches. Both the `nodeSelector` and this
  affinity key off `NodeGroupLabelKey` (the operator's configured grouping label),
  so they always match the label the operator actually groups by — even when it is
  overridden from the default `node.kubernetes.io/instance-type`.

The default group affinity carries **only** the `DoesNotExist` term; its OS
requirement is already enforced by the `nodeSelector`. Non-default groups are not
given an operator-managed affinity at all, so any user-provided `nodeAgent.affinity`
(zone / GPU / topology constraints) is preserved for them.

The label-less population is tracked under an internal sentinel key, so a node
that legitimately carries `<groupingLabel>=<defaultNodeGroup>` forms its own
normal (nodeSelector-targeted) group and is never merged into the affinity-based
default group.

> **Edge case — shared `kubescape.io/node-group` value.** In the unlikely event a
> node is *labelled* `<groupingLabel>=<defaultNodeGroup>` while other nodes lack
> the label, the real group and the synthetic default group both render their
> `kubescape.io/node-group` selector value as `<defaultNodeGroup>`, so the two
> DaemonSets share a pod selector. This is safe in practice — their node targeting
> is mutually exclusive (label-present vs. absent) and `ownerReferences` prevent
> pod adoption across them — but `kubectl get pods -l kubescape.io/node-group=…`
> will list both groups' pods together.

### NodeGrouper (`nodegrouper.go`)

Handles node discovery and resource calculation.

**Key Functions:**

| Function | Description |
|----------|-------------|
| `GetNodeGroups()` | Lists nodes, groups by label, returns `[]NodeGroup` |
| `CalculateResources()` | Computes resource requests/limits for a group |
| `sanitizeName()` | Converts label values to DNS-safe names |
| `resolveNameCollisions()` | Adds hash suffix when sanitized names collide |

**Resource Calculation:**

```go
func calculatePercentage(q resource.Quantity, percent int) resource.Quantity {
    // For memory (BinarySI): preserve proper units (Mi, Gi)
    if q.Format == resource.BinarySI {
        value := q.Value()
        result := value * int64(percent) / 100
        return *resource.NewQuantity(result, resource.BinarySI)
    }
    // For CPU: use milli-units for precision
    milliValue := q.MilliValue()
    result := milliValue * int64(percent) / 100
    return *resource.NewMilliQuantity(result, q.Format)
}
```

**Representative allocatable per group:**

Instance-type groups are homogeneous by definition, so a group's allocatable is
taken from the first node seen. The **default group** is the exception: label-less
nodes can be heterogeneous (mixed on-prem/bare-metal hardware), so it is sized off
the **minimum** allocatable CPU/memory across its nodes. This guarantees the
node-agent's requests fit every node in the group and makes the result independent
of the (unstable) node list order.

**Naming Collision Detection:**

Different label values can sanitize to the same name (e.g., `m5.large` and `m5_large` both become `m5-large`). The autoscaler detects this and adds a short hash suffix:

```go
// "m5.large"  → "m5-large-a1b2c3"
// "m5_large"  → "m5-large-d4e5f6"
func shortHash(input string) string {
    hash := sha256.Sum256([]byte(input))
    return hex.EncodeToString(hash[:])[:6]
}
```

### TemplateRenderer (`templaterenderer.go`)

Manages DaemonSet template loading and rendering.

**Key Features:**

1. **Template Loading**: Reads DaemonSet YAML template from ConfigMap mount
2. **Go Template Rendering**: Injects dynamic values (name, resources, node selector)
3. **File Watching**: Auto-reloads template when ConfigMap is updated (via `fsnotify`)
4. **Thread Safety**: Uses `sync.RWMutex` to protect template during reloads

**Template Data Structure:**

```go
type TemplateData struct {
    Name              string            // e.g., "node-agent-m5-large"
    NodeGroupLabel    string            // the group's label value, e.g., "m5.large"
    NodeGroupLabelKey string            // the configured grouping label key, e.g., "node.kubernetes.io/instance-type"
    IsDefaultGroup    bool              // true for the fallback group of label-less nodes
    Resources         TemplateResources // Requests and limits
}

type TemplateResources struct {
    Requests TemplateResourcePair  // {CPU: "100m", Memory: "200Mi"}
    Limits   TemplateResourcePair  // {CPU: "500m", Memory: "1Gi"}
}
```

**Memory Formatting:**

The `formatMemory()` function outputs human-readable memory values while preserving precision:

```go
func formatMemory(q resource.Quantity) string {
    bytes := q.Value()

    // Only use Gi for exact multiples (preserves precision)
    gi := int64(1024 * 1024 * 1024)
    if bytes >= gi && bytes%gi == 0 {
        return fmt.Sprintf("%dGi", bytes/gi)
    }

    // Use Mi for everything else
    mi := int64(1024 * 1024)
    if bytes >= mi {
        return fmt.Sprintf("%dMi", bytes/mi)
    }
    // ... Ki and bytes fallback
}
```

**File Watching for Auto-Reload:**

```go
func (tr *TemplateRenderer) StartWatching(ctx context.Context) error {
    watcher, _ := fsnotify.NewWatcher()

    // Watch the directory (ConfigMaps are symlink-swapped)
    dir := filepath.Dir(tr.templatePath)
    watcher.Add(dir)

    go tr.watchLoop(ctx)  // Reloads on Write/Create events
}
```

## Configuration

The autoscaler is configured via the operator's ConfigMap:

```go
type NodeAgentAutoscalerConfig struct {
    Enabled             bool          // Enable/disable autoscaler
    NodeGroupLabel      string        // Label to group nodes by
    DefaultNodeGroup    string        // Group value for nodes missing NodeGroupLabel (default: "default"; empty = skip)
    ResourcePercentages struct {
        RequestCPU    int  // % of allocatable CPU for requests
        RequestMemory int  // % of allocatable memory for requests
        LimitCPU      int  // % of allocatable CPU for limits
        LimitMemory   int  // % of allocatable memory for limits
    }
    MinResources struct {
        CPU    string  // e.g., "100m"
        Memory string  // e.g., "180Mi"
    }
    MaxResources struct {
        CPU    string  // e.g., "2000m"
        Memory string  // e.g., "4Gi"
    }
    ReconcileInterval      time.Duration  // How often to reconcile
    TemplatePath           string         // Path to DaemonSet template
    OperatorDeploymentName string         // For owner references
}
```

## Lifecycle Management

### Startup

```go
// In main.go
autoscalerConfig := operatorConfig.NodeAgentAutoscalerConfig()
if autoscalerConfig.Enabled {
    autoscaler, err := nodeagentautoscaler.NewAutoscaler(
        k8sApi.KubernetesClient,
        autoscalerConfig,
        operatorConfig.Namespace(),
        operatorDeploymentName,
    )
    if err != nil {
        logger.L().Ctx(ctx).Fatal("failed to initialize node agent autoscaler", ...)
    }
    go autoscaler.Start(ctx)
}
```

### Owner References (Garbage Collection)

DaemonSets are linked to the operator Deployment via owner references:

```go
func (a *Autoscaler) initOwnerReference(ctx context.Context) error {
    deployment, _ := a.client.AppsV1().Deployments(a.namespace).Get(ctx, a.operatorDeployment, ...)

    a.ownerRef = &metav1.OwnerReference{
        APIVersion:         "apps/v1",
        Kind:               "Deployment",
        Name:               deployment.Name,
        UID:                deployment.UID,
        BlockOwnerDeletion: &blockOwnerDeletion,
        Controller:         &controller,
    }
}
```

When the operator Deployment is deleted (e.g., `helm uninstall`), Kubernetes garbage collector automatically deletes all owned DaemonSets.

### Idempotent Updates

The autoscaler uses an "always update" strategy instead of comparing specs field-by-field:

```go
func (a *Autoscaler) updateDaemonSetIfNeeded(ctx context.Context, existing, desired *appsv1.DaemonSet) error {
    // Preserve existing metadata
    desired.ObjectMeta.ResourceVersion = existing.ObjectMeta.ResourceVersion

    // Always call Update() - Kubernetes handles idempotency
    // Pods only restart if PodTemplateSpec actually changes
    _, err := a.client.AppsV1().DaemonSets(a.namespace).Update(ctx, desired, metav1.UpdateOptions{})
    return err
}
```

**Benefits:**
- Simpler code (no field comparison logic)
- Catches all template changes automatically
- Safe: Kubernetes won't restart pods unless spec changes
- Low overhead for infrequent template changes

## Events

The autoscaler emits Kubernetes events for observability:

| Event | Type | When |
|-------|------|------|
| `Created` | Normal | New DaemonSet created for node group |
| `Deleted` | Normal | Orphaned DaemonSet removed |
| `Failed` | Warning | Create/Update/Delete operation failed |

```bash
kubectl get events -n kubescape --field-selector reason=Created,reason=Deleted
```

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Node missing group label (`DefaultNodeGroup` set) | Assign node to the default group (targeted via `DoesNotExist` affinity) so a node-agent is still deployed |
| Node missing group label (`DefaultNodeGroup` empty) | Log error, skip node (no DaemonSet for it) |
| Template parse error | Fatal error on startup |
| Template render error | Log error, skip node group |
| API error (create/update/delete) | Log error, continue reconciliation |
| Owner reference lookup failure | Log warning, continue without GC support |

## Testing

### Unit Tests

```bash
go test ./nodeagentautoscaler/... -v
```

### Integration Tests

Requires a Helm-generated template file:

```bash
# Extract template from Helm
helm template test ../../helm-charts/charts/kubescape-operator \
  --set nodeAgent.autoscaler.enabled=true --set clusterName=test \
  | grep -A 300 "daemonset-template.yaml:" | tail -n +2 | sed 's/^    //' \
  | awk '/^---/{exit} {print}' > /tmp/test-daemonset-template.yaml

# Run integration tests
go test -tags=integration -v -run TestIntegration_HelmGeneratedTemplate
```

## RBAC Requirements

The operator needs these permissions for the autoscaler:

```yaml
# Namespaced (Role)
- apiGroups: ["apps"]
  resources: ["daemonsets"]
  verbs: ["create", "get", "update", "watch", "list", "patch", "delete"]

# Cluster-scoped (ClusterRole)
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
```

## Debugging

### Check autoscaler logs

```bash
kubectl logs -n kubescape -l app=operator | grep -i autoscaler
```

### List managed DaemonSets

```bash
kubectl get ds -n kubescape -l kubescape.io/managed-by=operator-autoscaler
```

### Verify template is loaded

```bash
kubectl exec -n kubescape deploy/operator -- cat /etc/templates/daemonset-template.yaml
```

### Check for template reload events

```bash
kubectl logs -n kubescape -l app=operator | grep -i "template"
```

