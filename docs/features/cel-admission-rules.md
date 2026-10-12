# CEL-Driven Admission Rules

## Overview

The CEL admission rules feature replaces hardcoded admission webhook rules with
CRD-driven CEL (Common Expression Language) evaluation. Rules are stored in
`kubescape.io/v1` `Rules` CRDs and evaluated at admission time using a
configurable CEL engine.

## Architecture

```
Rules CRD  ──watch──▶  RulesWatcher  ──sync──▶  CelRuleCreator
                                                      │
                                                      ▼
Admission Webhook ──▶ RBCache.ListRulesForObject ──▶ CelRuleEvaluator
                                                      │
                                                      ▼
                                               AdmissionCEL.EvaluateRuleWithContext
```

## Components

### AdmissionCEL (`admission/cel/cel.go`)

CEL environment configured for evaluating expressions against admission events.
Compiled programs are cached for performance.

Variables available in expressions:

| Variable    | Type                        | Description                        |
|-------------|-----------------------------|------------------------------------|
| `event`     | `cel.AdmissionCelEvent`     | The full admission event           |
| `eventType` | `string`                    | Always `"k8s-admission"`           |
| `object`    | `map[string]any`            | Incoming object (new state)        |
| `oldObject` | `map[string]any`            | Previous object (for UPDATE)       |
| `options`   | `map[string]any`            | Admission options                  |

### CelRuleCreator (`admission/rules/cel/creator.go`)

Holds the active set of `armotypes.RuntimeRule` values and creates
`CelRuleEvaluator` instances on demand. The rule set is replaced atomically
via `SyncRules(rules []armotypes.RuntimeRule)`.

### CelRuleEvaluator (`admission/rules/cel/evaluator.go`)

Wraps a single `RuntimeRule` and implements `rules.RuleEvaluator`. Delegates
expression evaluation to `AdmissionCEL`.

### RulesWatcher (`admission/ruleswatcher/watcher.go`)

Implements `watcher.Adaptor`. Watches the `kubescape.io/v1/rules` CRD resource.
On any Add / Modify / Delete event it:

1. Lists all `Rules` CRDs.
2. Extracts `RuntimeRule` values from each CRD's `spec.rules` field.
3. Filters to rules that are `enabled` and have at least one expression with
   `eventType: k8s-admission`.
4. Calls `CelRuleCreator.SyncRules` with the filtered set.
5. Optionally calls `RBCacheRefresher.RefreshRules` to flush derived caches.

## Rule CRD Format

```yaml
apiVersion: kubescape.io/v1
kind: Rule
metadata:
  name: my-admission-rules
spec:
  rules:
    - id: "deny-privileged-containers"
      name: "Deny Privileged Containers"
      enabled: true
      expressions:
        ruleExpression:
          - eventType: "k8s-admission"
            expression: |
              object.spec.containers.exists(c,
                c.?securityContext.?privileged.orValue(false))
      severity: 8
      tags: ["security", "admission"]
```

## Alert Enrichment

After a rule matches, `CelRuleEvaluator` fills `RuntimeAlertK8sDetails` so the
backend can attach the alert to a pod and workload. The backend drops admission
alerts that lack `PodName` and `PodNamespace`, so this step decides whether an
alert ever becomes an incident.

| Request | Pod identity source | Fields populated |
|---|---|---|
| Pod CREATE | Decoded from the admission object (the pod is not persisted yet, a GET by name fails) | PodName, PodNamespace, Namespace, NodeName (if scheduled), Workload* from ownerReferences |
| exec, attach, portforward, Pod UPDATE/DELETE | GET pod by name; falls back to the admission object when the GET fails and the object is a Pod | Same as above, plus ContainerName, ContainerID, Image, ImageDigest for exec and attach |
| Non-pod kinds (RoleBinding, NetworkPolicy, ...) | None | None. These alerts have no pod identity and are dropped by the backend today |

`PodName` falls back to `metadata.name`, then `metadata.generateName`, when the
request carries no name yet. `ContainerName` is left empty unless the request
names a container; a Pod CREATE never guesses one.

`HTTPExporter.SendAdmissionAlert` sets `AlertSourcePlatform` to
`AlertSourcePlatformK8sAgent` explicitly. Without it the backend infers the
platform from `PodName` and classifies a pod-less alert as a Linux host alert.

Rules that target cluster-scoped or non-pod resources need a backend change
(an admission-request identity in incident correlation) before they can
produce incidents.

## Event Type Constant

`admission/cel/cel.go` defines:

```go
const EventTypeK8sAdmission armotypes.EventType = "k8s-admission"
```

This is defined locally because the pinned `armoapi-go` version does not yet
export this constant.

## Testing

```bash
# Unit tests for CEL engine
go test ./admission/cel/... -v

# Unit tests for CelRuleCreator and CelRuleEvaluator
go test ./admission/rules/cel/... -v

# Unit tests for RulesWatcher
go test ./admission/ruleswatcher/... -v
```
