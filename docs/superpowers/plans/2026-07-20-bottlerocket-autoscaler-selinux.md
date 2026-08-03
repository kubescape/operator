# Bottlerocket Auto-Detection in node-agent Autoscaler — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Kubescape operator's node-agent autoscaler auto-detect AWS Bottlerocket nodes and render those node groups' DaemonSets with `seLinuxOptions.type: super_t`, so customers no longer pass `--set nodeAgent.seLinuxType=super_t`.

**Architecture:** Mirror the autoscaler's existing per-group CPU/memory/`GOMEMLIMIT` pattern. The operator detects Bottlerocket per node group (`NodeGrouper`), selects the SELinux type per group (`TemplateRenderer`), and injects it through `TemplateData`; the Helm chart exposes an `autoscalerMode` Go-template placeholder the operator renders at runtime. Non-autoscaler installs are untouched.

**Tech Stack:** Go (operator, `client-go`, `text/template`, `viper`, `testify`), Helm (Go templates), YAML.

## Global Constraints

- **Scope:** autoscaler install path only (`nodeAgent.autoscaler.enabled=true`). Standard single-DaemonSet and `multipleDaemonSets` modes stay unchanged and keep honoring the helm-baked `nodeAgent.seLinuxType`.
- **Bottlerocket detection:** case-insensitive substring match of `"bottlerocket"` against `node.Status.NodeInfo.OSImage`. Version-independent.
- **Per-group flag:** a node group is Bottlerocket if **any** ready node in it is Bottlerocket.
- **Bottlerocket SELinux type value:** exactly `super_t`. Default/non-Bottlerocket value: `spc_t`.
- **Config knob names (verbatim):** `nodeAgentAutoscaler.seLinuxType` (default `spc_t`), `nodeAgentAutoscaler.bottlerocketAutoDetect` (default `true`). Chart values: `nodeAgent.seLinuxType` (existing) and new `nodeAgent.autoscaler.bottlerocketAutoDetect`.
- **Cross-repo:** operator image and chart ship together. Old template (no placeholder) rendered by new operator → renders the helm-baked literal, safe. New template rendered by old operator → leaves the literal `{{ .SELinuxType }}` string, so the chart bump must not reach clusters ahead of the operator image.
- **Repos:** operator at `operator/`, chart at `helm-charts/charts/kubescape-operator/`. Run all `go` commands from `operator/`.

---

## File Structure

**operator/** (Go)
- `config/config.go` — add two `NodeAgentAutoscalerConfig` fields + viper defaults.
- `config/config_test.go` — extend `TestLoadConfig` expectations.
- `nodeagentautoscaler/nodegrouper.go` — `NodeGroup.HasBottlerocket` field + detection.
- `nodeagentautoscaler/templaterenderer.go` — `TemplateData.SELinuxType`, renderer default field, `NewTemplateRenderer` param, per-group selection.
- `nodeagentautoscaler/autoscaler.go` — pass `cfg.SELinuxType` into `NewTemplateRenderer`.
- `nodeagentautoscaler/autoscaler_test.go` — grouper detection tests.
- `nodeagentautoscaler/templaterenderer_test.go` — renderer tests + fix existing constructor call sites.
- `nodeagentautoscaler/integration_test.go` — fix constructor call sites + Bottlerocket assertion.
- `docs/node-agent-autoscaler.md` — document the feature.

**helm-charts/charts/kubescape-operator/** (Helm)
- `templates/node-agent/_node-agent.tpl` — `autoscalerMode`-aware `seLinuxOptions`.
- `templates/operator/configmap.yaml` — add both fields to `config.json`.
- `values.yaml` — add `nodeAgent.autoscaler.bottlerocketAutoDetect: true`.
- `README.md` — document the new value.

---

## Task 1: Operator config fields + defaults

**Files:**
- Modify: `operator/config/config.go` (struct `NodeAgentAutoscalerConfig` ~line 69-84; `LoadConfig` viper defaults ~line 337)
- Test: `operator/config/config_test.go` (`TestLoadConfig` ~line 127-149)

**Interfaces:**
- Produces: `config.NodeAgentAutoscalerConfig.SELinuxType string` (json/mapstructure `seLinuxType`, default `"spc_t"`), `config.NodeAgentAutoscalerConfig.BottlerocketAutoDetect bool` (json/mapstructure `bottlerocketAutoDetect`, default `true`).

- [ ] **Step 1: Update the failing test first**

In `operator/config/config_test.go`, inside `TestLoadConfig`'s `want.NodeAgentAutoscaler` literal (after `GoMemLimitPercentage: 0.8,` at ~line 148), add:

```go
					GoMemLimitPercentage:   0.8,
					SELinuxType:            "spc_t",
					BottlerocketAutoDetect: true,
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd operator && go test ./config/ -run TestLoadConfig -v`
Expected: FAIL — `SELinuxType`/`BottlerocketAutoDetect` are undefined fields (compile error) or values mismatch.

- [ ] **Step 3: Add the struct fields**

In `operator/config/config.go`, in `type NodeAgentAutoscalerConfig struct`, after the `GoMemLimitPercentage` field, add:

```go
	GoMemLimitPercentage   float64                                `json:"goMemLimitPercentage" mapstructure:"goMemLimitPercentage"`
	// SELinuxType is the SELinux type applied to node-agent DaemonSets the
	// autoscaler renders for node groups that are NOT Bottlerocket. Sourced from
	// the chart's nodeAgent.seLinuxType (default "spc_t"). Bottlerocket groups
	// always override this with "super_t" when BottlerocketAutoDetect is enabled.
	SELinuxType string `json:"seLinuxType" mapstructure:"seLinuxType"`
	// BottlerocketAutoDetect, when true, makes the autoscaler detect AWS
	// Bottlerocket nodes and render their node group's DaemonSet with the
	// "super_t" SELinux type automatically. Set false to disable detection.
	BottlerocketAutoDetect bool `json:"bottlerocketAutoDetect" mapstructure:"bottlerocketAutoDetect"`
```

- [ ] **Step 4: Add the viper defaults**

In `operator/config/config.go` `LoadConfig`, after `viper.SetDefault("nodeAgentAutoscaler.goMemLimitPercentage", 0.8)` (~line 337), add:

```go
	viper.SetDefault("nodeAgentAutoscaler.goMemLimitPercentage", 0.8)
	viper.SetDefault("nodeAgentAutoscaler.seLinuxType", "spc_t")
	viper.SetDefault("nodeAgentAutoscaler.bottlerocketAutoDetect", true)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd operator && go test ./config/ -run TestLoadConfig -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd operator
git add config/config.go config/config_test.go
git commit -m "feat(autoscaler): add seLinuxType and bottlerocketAutoDetect config"
```

---

## Task 2: Bottlerocket detection in NodeGrouper

**Files:**
- Modify: `operator/nodeagentautoscaler/nodegrouper.go` (`NodeGroup` struct ~line 24-40; `GetNodeGroups` loop ~line 80-138)
- Test: `operator/nodeagentautoscaler/autoscaler_test.go` (add a new test function)

**Interfaces:**
- Consumes: `config.NodeAgentAutoscalerConfig.BottlerocketAutoDetect` (Task 1).
- Produces: `NodeGroup.HasBottlerocket bool`; unexported helper `isBottlerocketNode(node *corev1.Node) bool`.

- [ ] **Step 1: Write the failing test**

In `operator/nodeagentautoscaler/autoscaler_test.go`, append a new test. It builds nodes with an OS image and asserts the per-group flag and the toggle. `strings`/`fake`/`corev1`/`resource`/`metav1`/`config`/`require`/`assert` are already imported in this file.

```go
func TestNodeGrouper_GetNodeGroups_BottlerocketDetection(t *testing.T) {
	ctx := context.Background()

	newNode := func(name, instanceType, osImage string) *corev1.Node {
		return &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   name,
				Labels: map[string]string{"node.kubernetes.io/instance-type": instanceType},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi"),
				},
				NodeInfo: corev1.NodeSystemInfo{OSImage: osImage},
			},
		}
	}

	findGroup := func(groups []NodeGroup, label string) *NodeGroup {
		for i := range groups {
			if groups[i].LabelValue == label {
				return &groups[i]
			}
		}
		return nil
	}

	t.Run("group with a bottlerocket node is flagged (case-insensitive)", func(t *testing.T) {
		client := fake.NewClientset(
			newNode("n1", "m5.large", "Bottlerocket OS 1.19.2 (aws-k8s-1.29)"),
			newNode("n2", "m5.xlarge", "Amazon Linux 2"),
		)
		cfg := config.NodeAgentAutoscalerConfig{Enabled: true, NodeGroupLabel: "node.kubernetes.io/instance-type", BottlerocketAutoDetect: true}
		groups, err := NewNodeGrouper(client, cfg, "kubescape").GetNodeGroups(ctx)
		require.NoError(t, err)
		assert.True(t, findGroup(groups, "m5.large").HasBottlerocket)
		assert.False(t, findGroup(groups, "m5.xlarge").HasBottlerocket)
	})

	t.Run("mixed group with any bottlerocket node is flagged", func(t *testing.T) {
		client := fake.NewClientset(
			newNode("n1", "m5.large", "Amazon Linux 2"),
			newNode("n2", "m5.large", "bottlerocket os 1.20.0"),
		)
		cfg := config.NodeAgentAutoscalerConfig{Enabled: true, NodeGroupLabel: "node.kubernetes.io/instance-type", BottlerocketAutoDetect: true}
		groups, err := NewNodeGrouper(client, cfg, "kubescape").GetNodeGroups(ctx)
		require.NoError(t, err)
		assert.True(t, findGroup(groups, "m5.large").HasBottlerocket)
	})

	t.Run("toggle off never flags", func(t *testing.T) {
		client := fake.NewClientset(newNode("n1", "m5.large", "Bottlerocket OS 1.19.2"))
		cfg := config.NodeAgentAutoscalerConfig{Enabled: true, NodeGroupLabel: "node.kubernetes.io/instance-type", BottlerocketAutoDetect: false}
		groups, err := NewNodeGrouper(client, cfg, "kubescape").GetNodeGroups(ctx)
		require.NoError(t, err)
		assert.False(t, findGroup(groups, "m5.large").HasBottlerocket)
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd operator && go test ./nodeagentautoscaler/ -run TestNodeGrouper_GetNodeGroups_BottlerocketDetection -v`
Expected: FAIL — `HasBottlerocket` is an undefined field (compile error).

- [ ] **Step 3: Add the `HasBottlerocket` field**

In `operator/nodeagentautoscaler/nodegrouper.go`, in `type NodeGroup struct`, after the `IsDefault bool` field (~line 39), add:

```go
	IsDefault bool
	// HasBottlerocket is true when at least one ready node in this group runs AWS
	// Bottlerocket OS. Such groups get the "super_t" SELinux type. Detection is
	// gated by config.BottlerocketAutoDetect.
	HasBottlerocket bool
```

- [ ] **Step 4: Add the detection helper**

In `operator/nodeagentautoscaler/nodegrouper.go`, near `isNodeReady` (bottom of file), add:

```go
// isBottlerocketNode reports whether a node runs AWS Bottlerocket OS. It matches
// case-insensitively against the reported OS image, e.g.
// "Bottlerocket OS 1.19.2 (aws-k8s-1.29)".
func isBottlerocketNode(node *corev1.Node) bool {
	return strings.Contains(strings.ToLower(node.Status.NodeInfo.OSImage), "bottlerocket")
}
```

- [ ] **Step 5: Wire detection into the grouping loop**

In `operator/nodeagentautoscaler/nodegrouper.go` `GetNodeGroups`, inside the `for _, node := range nodes.Items` loop, right after the `if !isNodeReady(&node) { continue }` block (~line 84), add:

```go
		nodeIsBottlerocket := ng.config.BottlerocketAutoDetect && isBottlerocketNode(&node)
```

Then in the `if group, exists := groupMap[groupKey]; exists {` branch, after `group.NodeCount++` (~line 114), add:

```go
			if nodeIsBottlerocket {
				group.HasBottlerocket = true
			}
```

And in the `else {` branch where the new `&NodeGroup{...}` literal is built (~line 129), add the field:

```go
				NodeCount:         1,
				IsDefault:         isDefault,
				HasBottlerocket:   nodeIsBottlerocket,
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd operator && go test ./nodeagentautoscaler/ -run TestNodeGrouper_GetNodeGroups_BottlerocketDetection -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd operator
git add nodeagentautoscaler/nodegrouper.go nodeagentautoscaler/autoscaler_test.go
git commit -m "feat(autoscaler): detect Bottlerocket nodes per node group"
```

---

## Task 3: Per-group SELinux type selection in the renderer

**Files:**
- Modify: `operator/nodeagentautoscaler/templaterenderer.go` (`TemplateData` ~line 21-39; `TemplateRenderer` struct ~line 54-62; `NewTemplateRenderer` ~line 65-81; `RenderDaemonSet` ~line 221-241)
- Modify: `operator/nodeagentautoscaler/autoscaler.go` (`NewAutoscaler`, `NewTemplateRenderer` call)
- Test: `operator/nodeagentautoscaler/templaterenderer_test.go` (new test + fix existing call sites)
- Modify: `operator/nodeagentautoscaler/integration_test.go` (fix call sites + assertion)

**Interfaces:**
- Consumes: `NodeGroup.HasBottlerocket` (Task 2), `config.SELinuxType` (Task 1).
- Produces: `NewTemplateRenderer(templatePath string, goMemLimitPercentage float64, nodeGroupLabelKey string, defaultSELinuxType string) (*TemplateRenderer, error)`; `TemplateData.SELinuxType string`.

- [ ] **Step 1: Write the failing test**

In `operator/nodeagentautoscaler/templaterenderer_test.go`, append:

```go
func TestTemplateRenderer_RenderDaemonSet_SELinuxType(t *testing.T) {
	templateContent := `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: "{{ .Name }}"
  namespace: kubescape
spec:
  template:
    spec:
      containers:
      - name: node-agent
        securityContext:
          seLinuxOptions:
            type: {{ .SELinuxType }}
`
	dir := t.TempDir()
	templatePath := filepath.Join(dir, "daemonset-template.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(templateContent), 0644))

	renderer, err := NewTemplateRenderer(templatePath, 0.8, "node.kubernetes.io/instance-type", "spc_t")
	require.NoError(t, err)

	resources := CalculatedResources{
		Requests: ResourcePair{CPU: resource.MustParse("100m"), Memory: resource.MustParse("200Mi")},
		Limits:   ResourcePair{CPU: resource.MustParse("500m"), Memory: resource.MustParse("1Gi")},
	}

	t.Run("bottlerocket group gets super_t", func(t *testing.T) {
		ds, err := renderer.RenderDaemonSet(NodeGroup{LabelValue: "m5.large", SanitizedName: "m5-large", HasBottlerocket: true}, resources)
		require.NoError(t, err)
		assert.Equal(t, corev1.SELinuxType("super_t"), ds.Spec.Template.Spec.Containers[0].SecurityContext.SELinuxOptions.Type)
	})

	t.Run("non-bottlerocket group gets configured default", func(t *testing.T) {
		ds, err := renderer.RenderDaemonSet(NodeGroup{LabelValue: "m5.large", SanitizedName: "m5-large", HasBottlerocket: false}, resources)
		require.NoError(t, err)
		assert.Equal(t, corev1.SELinuxType("spc_t"), ds.Spec.Template.Spec.Containers[0].SecurityContext.SELinuxOptions.Type)
	})
}
```

Note: `corev1.SELinuxOptions.Type` is a `corev1.SELinuxType` (a string alias); compare against `corev1.SELinuxType("super_t")`. `corev1` is already imported in this test file.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd operator && go test ./nodeagentautoscaler/ -run TestTemplateRenderer_RenderDaemonSet_SELinuxType -v`
Expected: FAIL — `NewTemplateRenderer` takes 3 args, not 4 (compile error), and `TemplateData` has no `SELinuxType`.

- [ ] **Step 3: Add the const and `TemplateData` field**

In `operator/nodeagentautoscaler/templaterenderer.go`, add a package const near the top (after the imports):

```go
// bottlerocketSELinuxType is the SELinux type node-agent needs on AWS Bottlerocket
// nodes so its eBPF gadgets get the required privileges.
const bottlerocketSELinuxType = "super_t"
```

In `type TemplateData struct`, after `GoMemLimit string` (~line 38), add:

```go
	GoMemLimit string
	// SELinuxType is the SELinux type rendered into the node-agent container's
	// securityContext ("super_t" for Bottlerocket groups, otherwise the configured default).
	SELinuxType string
```

- [ ] **Step 4: Add the renderer field and constructor param**

In `type TemplateRenderer struct`, after `nodeGroupLabelKey string` (~line 61), add:

```go
	nodeGroupLabelKey    string // configured grouping label key, exposed to the template
	defaultSELinuxType   string // SELinux type for non-Bottlerocket groups (e.g. "spc_t")
```

Change `NewTemplateRenderer` signature and body:

```go
func NewTemplateRenderer(templatePath string, goMemLimitPercentage float64, nodeGroupLabelKey string, defaultSELinuxType string) (*TemplateRenderer, error) {
	if goMemLimitPercentage <= 0 || goMemLimitPercentage > 1.0 {
		return nil, fmt.Errorf("goMemLimitPercentage %v is out of valid range (0, 1.0]", goMemLimitPercentage)
	}

	tr := &TemplateRenderer{
		templatePath:         templatePath,
		goMemLimitPercentage: goMemLimitPercentage,
		nodeGroupLabelKey:    nodeGroupLabelKey,
		defaultSELinuxType:   defaultSELinuxType,
	}

	if err := tr.loadTemplate(); err != nil {
		return nil, err
	}

	return tr, nil
}
```

- [ ] **Step 5: Select the type in `RenderDaemonSet`**

In `RenderDaemonSet`, before building `data := TemplateData{...}` (~line 225), add:

```go
	seLinuxType := tr.defaultSELinuxType
	if group.HasBottlerocket {
		seLinuxType = bottlerocketSELinuxType
	}
```

Then add the field to the `TemplateData` literal, after `GoMemLimit: ...` (~line 240):

```go
		GoMemLimit:  fmt.Sprintf("%dMiB", goMemLimitMiB),
		SELinuxType: seLinuxType,
```

- [ ] **Step 6: Update the production call site**

In `operator/nodeagentautoscaler/autoscaler.go`, in `NewAutoscaler`, change:

```go
	templateRenderer, err := NewTemplateRenderer(cfg.TemplatePath, cfg.GoMemLimitPercentage, cfg.NodeGroupLabel, cfg.SELinuxType)
```

- [ ] **Step 7: Fix existing test call sites (compile fix)**

Every existing `NewTemplateRenderer(...)` call in tests takes 3 args and must gain a 4th (`"spc_t"`). Update all call sites in `operator/nodeagentautoscaler/templaterenderer_test.go` and `operator/nodeagentautoscaler/integration_test.go`. Find them:

Run: `cd operator && grep -rn "NewTemplateRenderer(" nodeagentautoscaler/*_test.go`

For each match, append `, "spc_t"` as the final argument. Example — the invalid-percentage test intentionally passes a bad percentage; keep that and still add the type:

```go
	_, err = NewTemplateRenderer(templatePath, 1.0, "node.kubernetes.io/instance-type", "spc_t")
```

- [ ] **Step 8: Run the new test and the whole package**

Run: `cd operator && go test ./nodeagentautoscaler/ -run TestTemplateRenderer_RenderDaemonSet_SELinuxType -v`
Expected: PASS.

Run: `cd operator && go build ./... && go test ./nodeagentautoscaler/ ./config/`
Expected: build OK, all tests PASS (existing tests compile with the new 4-arg constructor).

- [ ] **Step 9: Commit**

```bash
cd operator
git add nodeagentautoscaler/templaterenderer.go nodeagentautoscaler/autoscaler.go nodeagentautoscaler/templaterenderer_test.go nodeagentautoscaler/integration_test.go
git commit -m "feat(autoscaler): render super_t SELinux type for Bottlerocket groups"
```

---

## Task 4: Helm template — autoscalerMode-aware seLinuxOptions

**Files:**
- Modify: `helm-charts/charts/kubescape-operator/templates/node-agent/_node-agent.tpl` (~line 229-230, inside `define "node-agent.container"` which receives `.autoscalerMode`)

**Interfaces:**
- Consumes: `.autoscalerMode` (already threaded into `node-agent.container` at call site line ~504); `.SELinuxType` (rendered by the operator, Task 3); `.Values.nodeAgent.seLinuxType` (existing chart value).

- [ ] **Step 1: Make the seLinuxOptions block conditional**

In `helm-charts/charts/kubescape-operator/templates/node-agent/_node-agent.tpl`, replace:

```yaml
    seLinuxOptions:
      type: {{ .Values.nodeAgent.seLinuxType }}
```

with:

```yaml
    seLinuxOptions:
      {{- if .autoscalerMode }}
      type: "{{`{{ .SELinuxType }}`}}"
      {{- else }}
      type: {{ .Values.nodeAgent.seLinuxType }}
      {{- end }}
```

In autoscaler mode Helm emits the literal placeholder `type: "{{ .SELinuxType }}"` (the operator renders it per group). In all other modes it emits the helm-baked value, exactly as today.

- [ ] **Step 2: Verify autoscaler mode emits the placeholder**

Run:
```bash
cd helm-charts/charts/kubescape-operator
helm template test . --set nodeAgent.autoscaler.enabled=true --set clusterName=test \
  | grep -A1 "seLinuxOptions"
```
Expected: the rendered ConfigMap's template contains `type: "{{ .SELinuxType }}"` (the placeholder, not a resolved value).

- [ ] **Step 3: Verify standard mode still bakes the value**

Run:
```bash
cd helm-charts/charts/kubescape-operator
helm template test . --set clusterName=test --set nodeAgent.seLinuxType=super_t \
  | grep -A1 "seLinuxOptions"
```
Expected: `type: super_t` (resolved literal — non-autoscaler DaemonSet, unchanged behavior).

- [ ] **Step 4: Commit**

```bash
cd helm-charts
git add charts/kubescape-operator/templates/node-agent/_node-agent.tpl
git commit -m "feat(node-agent): render SELinux type placeholder in autoscaler mode"
```

---

## Task 5: Helm config wiring (config.json + values.yaml)

**Files:**
- Modify: `helm-charts/charts/kubescape-operator/templates/operator/configmap.yaml` (the `config.json` `nodeAgentAutoscaler` block)
- Modify: `helm-charts/charts/kubescape-operator/values.yaml` (`nodeAgent.autoscaler` block ~line 795-817)
- Modify: `helm-charts/charts/kubescape-operator/README.md`

**Interfaces:**
- Consumes: `.Values.nodeAgent.seLinuxType` (existing), new `.Values.nodeAgent.autoscaler.bottlerocketAutoDetect`.
- Produces: `config.json` keys `nodeAgentAutoscaler.seLinuxType` and `nodeAgentAutoscaler.bottlerocketAutoDetect` (consumed by Task 1's operator config).

- [ ] **Step 1: Add the value with a default**

In `helm-charts/charts/kubescape-operator/values.yaml`, inside the `nodeAgent.autoscaler:` block, add:

```yaml
    # When true, the operator auto-detects AWS Bottlerocket nodes and renders
    # their node group's node-agent DaemonSet with seLinuxType "super_t"
    # automatically, so you don't need --set nodeAgent.seLinuxType=super_t.
    bottlerocketAutoDetect: true
```

- [ ] **Step 2: Wire both fields into config.json**

In `helm-charts/charts/kubescape-operator/templates/operator/configmap.yaml`, locate the `nodeAgentAutoscaler` object inside `config.json`. Add these two keys to it (match the surrounding JSON formatting/commas):

```yaml
        "seLinuxType": {{ .Values.nodeAgent.seLinuxType | quote }},
        "bottlerocketAutoDetect": {{ .Values.nodeAgent.autoscaler.bottlerocketAutoDetect }}
```

Place them so the resulting JSON is valid (the last key in the object has no trailing comma). If `nodeAgentAutoscaler` is emitted via a range/spread, add them as sibling literal keys following the existing `goMemLimitPercentage` key pattern.

- [ ] **Step 3: Verify config.json is valid and carries the fields**

Run:
```bash
cd helm-charts/charts/kubescape-operator
helm template test . --set nodeAgent.autoscaler.enabled=true --set clusterName=test \
  | grep -E "seLinuxType|bottlerocketAutoDetect"
```
Expected: both keys present, e.g. `"seLinuxType": "spc_t"` and `"bottlerocketAutoDetect": true`.

Run (validate the operator ConfigMap's `config.json` parses as JSON):
```bash
cd helm-charts/charts/kubescape-operator
helm template test . --set nodeAgent.autoscaler.enabled=true --set clusterName=test \
  --show-only templates/operator/configmap.yaml
```
Expected: renders without error; the `config.json` block is well-formed (no dangling commas).

- [ ] **Step 4: Document the value in the chart README**

In `helm-charts/charts/kubescape-operator/README.md`, add a row/entry for `nodeAgent.autoscaler.bottlerocketAutoDetect` (default `true`) describing that it auto-sets `super_t` on detected Bottlerocket node groups when the autoscaler is enabled.

- [ ] **Step 5: Commit**

```bash
cd helm-charts
git add charts/kubescape-operator/values.yaml charts/kubescape-operator/templates/operator/configmap.yaml charts/kubescape-operator/README.md
git commit -m "feat(autoscaler): wire seLinuxType and bottlerocketAutoDetect into operator config"
```

---

## Task 6: Integration test + operator docs

**Files:**
- Modify: `operator/nodeagentautoscaler/integration_test.go` (add a Bottlerocket assertion using the Helm-generated template)
- Modify: `operator/docs/node-agent-autoscaler.md`

**Interfaces:**
- Consumes: the Helm-generated template (Task 4/5), `RenderDaemonSet` with `HasBottlerocket` (Tasks 2/3).

- [ ] **Step 1: Add an integration test asserting super_t from the real template**

In `operator/nodeagentautoscaler/integration_test.go`, append (the file is already `//go:build integration` and imports `corev1`):

```go
// TestIntegration_HelmGeneratedTemplate_Bottlerocket verifies the Helm-generated
// autoscaler template renders super_t for a Bottlerocket group and the default for others.
func TestIntegration_HelmGeneratedTemplate_Bottlerocket(t *testing.T) {
	templatePath := "/tmp/test-daemonset-template.yaml"
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		t.Skip("Integration test requires template file. Run Helm extraction first. See test comments for instructions.")
	}

	renderer, err := NewTemplateRenderer(templatePath, 0.8, "node.kubernetes.io/instance-type", "spc_t")
	require.NoError(t, err)

	resources := CalculatedResources{
		Requests: ResourcePair{CPU: resource.MustParse("100m"), Memory: resource.MustParse("200Mi")},
		Limits:   ResourcePair{CPU: resource.MustParse("500m"), Memory: resource.MustParse("1Gi")},
	}

	brDS, err := renderer.RenderDaemonSet(NodeGroup{LabelValue: "m5.large", SanitizedName: "m5-large", HasBottlerocket: true}, resources)
	require.NoError(t, err)
	require.NotNil(t, brDS.Spec.Template.Spec.Containers[0].SecurityContext.SELinuxOptions)
	assert.Equal(t, corev1.SELinuxType("super_t"), brDS.Spec.Template.Spec.Containers[0].SecurityContext.SELinuxOptions.Type)

	stdDS, err := renderer.RenderDaemonSet(NodeGroup{LabelValue: "m5.large", SanitizedName: "m5-large", HasBottlerocket: false}, resources)
	require.NoError(t, err)
	require.NotNil(t, stdDS.Spec.Template.Spec.Containers[0].SecurityContext.SELinuxOptions)
	assert.Equal(t, corev1.SELinuxType("spc_t"), stdDS.Spec.Template.Spec.Containers[0].SecurityContext.SELinuxOptions.Type)
}
```

- [ ] **Step 2: Run the integration test against the real Helm template**

Run:
```bash
cd operator
helm template test ../helm-charts/charts/kubescape-operator \
  --set nodeAgent.autoscaler.enabled=true --set clusterName=test \
  | grep -A 300 "daemonset-template.yaml:" | tail -n +2 | sed 's/^    //' \
  | awk '/^---/{exit} {print}' > /tmp/test-daemonset-template.yaml
go test -tags=integration ./nodeagentautoscaler/ -run TestIntegration_HelmGeneratedTemplate_Bottlerocket -v
```
Expected: PASS (super_t for the Bottlerocket group, spc_t otherwise).

- [ ] **Step 3: Document the feature**

In `operator/docs/node-agent-autoscaler.md`, add a section "AWS Bottlerocket auto-detection" covering: the operator detects Bottlerocket nodes via `node.Status.NodeInfo.OSImage`; per-group `super_t` is applied automatically when the autoscaler is enabled; it is controlled by `nodeAgent.autoscaler.bottlerocketAutoDetect` (default `true`); customers no longer need `--set nodeAgent.seLinuxType=super_t`; mixed groups get `super_t` on all nodes in the group.

- [ ] **Step 4: Commit**

```bash
cd operator
git add nodeagentautoscaler/integration_test.go docs/node-agent-autoscaler.md
git commit -m "test(autoscaler): integration coverage for Bottlerocket super_t + docs"
```

---

## Final verification

- [ ] **Operator: full build, vet, and tests (incl. integration + race)**

```bash
cd operator
go build ./...
go vet ./...
go test ./config/ ./nodeagentautoscaler/
helm template test ../helm-charts/charts/kubescape-operator \
  --set nodeAgent.autoscaler.enabled=true --set clusterName=test \
  | grep -A 300 "daemonset-template.yaml:" | tail -n +2 | sed 's/^    //' \
  | awk '/^---/{exit} {print}' > /tmp/test-daemonset-template.yaml
go test -tags=integration ./nodeagentautoscaler/
go test -race ./nodeagentautoscaler/
```
Expected: all PASS.

- [ ] **Helm: lint + render both modes**

```bash
cd helm-charts/charts/kubescape-operator
helm lint . --set clusterName=test
helm template test . --set clusterName=test | grep -A1 seLinuxOptions          # standard: resolved literal
helm template test . --set nodeAgent.autoscaler.enabled=true --set clusterName=test | grep -E "SELinuxType|seLinuxType|bottlerocketAutoDetect"
```
Expected: lint clean; standard mode resolves `type: spc_t`; autoscaler mode shows the `{{ .SELinuxType }}` placeholder and both config.json keys.

## Notes for the executor

- **Cross-repo merge order:** merge/ship the **operator** change first (or together). A new chart template rendered by an old operator leaves the literal `{{ .SELinuxType }}` — don't let the chart bump reach clusters ahead of the operator image.
- **`multipleDaemonSets` mode** uses the same `_node-agent.tpl` container helper with `autoscalerMode=false`, so it keeps the helm-baked `nodeAgent.seLinuxType` — no change needed there; confirm via `helm template ... --set nodeAgent.multipleDaemonSets.enabled=true`.
- If the chart's `config.json` in `configmap.yaml` builds `nodeAgentAutoscaler` from a shared helper rather than inline literals, add the two keys wherever the existing `goMemLimitPercentage` key is emitted, preserving valid JSON.
