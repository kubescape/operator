package nodeagentautoscaler

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/operator/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple name",
			input:    "m5.large",
			expected: "m5-large",
		},
		{
			name:     "complex name",
			input:    "Standard_D4s_v3",
			expected: "standard-d4s-v3",
		},
		{
			name:     "with special chars",
			input:    "n1-standard-4@us-central1",
			expected: "n1-standard-4-us-central1",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "default",
		},
		{
			name:     "only special chars",
			input:    "...",
			expected: "default",
		},
		{
			name:     "very long name",
			input:    "this-is-a-very-long-instance-type-name-that-exceeds-the-maximum-allowed-length-for-dns-names",
			expected: "this-is-a-very-long-instance-type-name-that-exceed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculatePercentage(t *testing.T) {
	tests := []struct {
		name     string
		quantity resource.Quantity
		percent  int
		expected int64 // milli-value
	}{
		{
			name:     "2 percent of 4 cores",
			quantity: resource.MustParse("4"),
			percent:  2,
			expected: 80, // 4000m * 0.02 = 80m
		},
		{
			name:     "100 percent",
			quantity: resource.MustParse("1000m"),
			percent:  100,
			expected: 1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculatePercentage(tt.quantity, tt.percent)
			assert.Equal(t, tt.expected, result.MilliValue())
		})
	}

	// Test memory separately due to different scale
	t.Run("5 percent of 8Gi memory", func(t *testing.T) {
		quantity := resource.MustParse("8Gi")
		result := calculatePercentage(quantity, 5)
		// 8Gi = 8589934592 bytes, 5% = 429496729 bytes = ~409Mi
		// The Value() should be approximately 429496729 bytes
		assert.True(t, result.Value() > 400*1024*1024, "should be > 400Mi")
		assert.True(t, result.Value() < 450*1024*1024, "should be < 450Mi")
	})
}

func TestClampQuantity(t *testing.T) {
	tests := []struct {
		name     string
		quantity resource.Quantity
		min      resource.Quantity
		max      resource.Quantity
		expected resource.Quantity
	}{
		{
			name:     "within bounds",
			quantity: resource.MustParse("500m"),
			min:      resource.MustParse("100m"),
			max:      resource.MustParse("1000m"),
			expected: resource.MustParse("500m"),
		},
		{
			name:     "below min",
			quantity: resource.MustParse("50m"),
			min:      resource.MustParse("100m"),
			max:      resource.MustParse("1000m"),
			expected: resource.MustParse("100m"),
		},
		{
			name:     "above max",
			quantity: resource.MustParse("2000m"),
			min:      resource.MustParse("100m"),
			max:      resource.MustParse("1000m"),
			expected: resource.MustParse("1000m"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := clampQuantity(tt.quantity, tt.min, tt.max)
			assert.Equal(t, tt.expected.MilliValue(), result.MilliValue())
		})
	}
}

func TestNodeGrouper_GetNodeGroups(t *testing.T) {
	ctx := context.Background()

	// Create test nodes
	nodes := []runtime.Object{
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node1",
				Labels: map[string]string{
					"node.kubernetes.io/instance-type": "m5.large",
				},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi"),
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node2",
				Labels: map[string]string{
					"node.kubernetes.io/instance-type": "m5.large",
				},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi"),
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node3",
				Labels: map[string]string{
					"node.kubernetes.io/instance-type": "m5.xlarge",
				},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("8"),
					corev1.ResourceMemory: resource.MustParse("32Gi"),
				},
			},
		},
	}

	client := fake.NewClientset(nodes...)

	cfg := config.NodeAgentAutoscalerConfig{
		Enabled:        true,
		NodeGroupLabel: "node.kubernetes.io/instance-type",
	}

	ng := NewNodeGrouper(client, cfg, "kubescape")
	groups, err := ng.GetNodeGroups(ctx)

	require.NoError(t, err)
	assert.Len(t, groups, 2)

	// Find the groups
	var m5Large, m5XLarge *NodeGroup
	for i := range groups {
		if groups[i].LabelValue == "m5.large" {
			m5Large = &groups[i]
		} else if groups[i].LabelValue == "m5.xlarge" {
			m5XLarge = &groups[i]
		}
	}

	require.NotNil(t, m5Large)
	assert.Equal(t, 2, m5Large.NodeCount)
	assert.Equal(t, "m5-large", m5Large.SanitizedName)

	require.NotNil(t, m5XLarge)
	assert.Equal(t, 1, m5XLarge.NodeCount)
	assert.Equal(t, "m5-xlarge", m5XLarge.SanitizedName)
}

func TestNodeGrouper_GetNodeGroups_SkipsNodesWithoutLabel(t *testing.T) {
	ctx := context.Background()

	// Create test nodes - one with label, one without
	nodes := []runtime.Object{
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node-with-label",
				Labels: map[string]string{
					"node.kubernetes.io/instance-type": "m5.large",
				},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi"),
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "node-without-label",
				Labels: map[string]string{}, // No instance-type label
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi"),
				},
			},
		},
	}

	client := fake.NewClientset(nodes...)

	cfg := config.NodeAgentAutoscalerConfig{
		Enabled:        true,
		NodeGroupLabel: "node.kubernetes.io/instance-type",
	}

	ng := NewNodeGrouper(client, cfg, "kubescape")
	groups, err := ng.GetNodeGroups(ctx)

	require.NoError(t, err)
	// Should only have 1 group (node without label is skipped)
	assert.Len(t, groups, 1)
	assert.Equal(t, "m5.large", groups[0].LabelValue)
	assert.Equal(t, 1, groups[0].NodeCount)
}

func TestNodeGrouper_GetNodeGroups_DefaultNodeGroup(t *testing.T) {
	ctx := context.Background()

	// Two nodes without the grouping label, one with it.
	nodes := []runtime.Object{
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node-with-label",
				Labels: map[string]string{
					"node.kubernetes.io/instance-type": "m5.large",
				},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi"),
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "node-without-label-1",
				Labels: map[string]string{},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("8"),
					corev1.ResourceMemory: resource.MustParse("32Gi"),
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "node-without-label-2",
				Labels: map[string]string{},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("8"),
					corev1.ResourceMemory: resource.MustParse("32Gi"),
				},
			},
		},
	}

	client := fake.NewClientset(nodes...)

	cfg := config.NodeAgentAutoscalerConfig{
		Enabled:          true,
		NodeGroupLabel:   "node.kubernetes.io/instance-type",
		DefaultNodeGroup: "default",
	}

	ng := NewNodeGrouper(client, cfg, "kubescape")
	groups, err := ng.GetNodeGroups(ctx)

	require.NoError(t, err)
	// Both unlabeled nodes collapse into the "default" group alongside the labeled one.
	assert.Len(t, groups, 2)

	byLabel := make(map[string]NodeGroup, len(groups))
	for _, g := range groups {
		byLabel[g.LabelValue] = g
	}
	require.Contains(t, byLabel, "default")
	assert.Equal(t, 2, byLabel["default"].NodeCount)
	assert.True(t, byLabel["default"].IsDefault, "fallback group must be flagged IsDefault")
	require.Contains(t, byLabel, "m5.large")
	assert.Equal(t, 1, byLabel["m5.large"].NodeCount)
	assert.False(t, byLabel["m5.large"].IsDefault, "a labelled group must not be flagged IsDefault")
}

// TestNodeGrouper_GetNodeGroups_DefaultValueCollision ensures a node legitimately
// labelled "<groupingLabel>=default" is NOT merged with the synthetic fallback group
// of label-less nodes: they must stay distinct groups with distinct names so the
// labelled node keeps a nodeSelector-targeted DaemonSet (not the DoesNotExist path).
func TestNodeGrouper_GetNodeGroups_DefaultValueCollision(t *testing.T) {
	ctx := context.Background()

	newNode := func(name string, labels map[string]string) *corev1.Node {
		return &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi"),
				},
			},
		}
	}

	nodes := []runtime.Object{
		// A node legitimately labelled with the value "default".
		newNode("labelled-default", map[string]string{"node.kubernetes.io/instance-type": "default"}),
		// Two nodes missing the grouping label entirely.
		newNode("no-label-1", map[string]string{}),
		newNode("no-label-2", map[string]string{}),
	}

	client := fake.NewClientset(nodes...)
	cfg := config.NodeAgentAutoscalerConfig{
		Enabled:          true,
		NodeGroupLabel:   "node.kubernetes.io/instance-type",
		DefaultNodeGroup: "default",
	}

	groups, err := NewNodeGrouper(client, cfg, "kubescape").GetNodeGroups(ctx)
	require.NoError(t, err)

	// Two distinct groups, not one merged bucket.
	require.Len(t, groups, 2)

	var labelled, fallback *NodeGroup
	for i := range groups {
		if groups[i].IsDefault {
			fallback = &groups[i]
		} else {
			labelled = &groups[i]
		}
	}

	require.NotNil(t, labelled, "the legitimately labelled =default node must form its own group")
	assert.Equal(t, 1, labelled.NodeCount)
	assert.False(t, labelled.IsDefault)

	require.NotNil(t, fallback, "label-less nodes must form the fallback group")
	assert.Equal(t, 2, fallback.NodeCount)
	assert.True(t, fallback.IsDefault)

	// Names must be unique so they render to distinct DaemonSets.
	assert.NotEqual(t, labelled.SanitizedName, fallback.SanitizedName)
}

// TestNodeGrouper_GetNodeGroups_DefaultGroupSizesOffMinimum verifies the
// heterogeneous default group is sized from the minimum allocatable across its
// nodes (a safe lower bound), not the arbitrary first-listed node.
func TestNodeGrouper_GetNodeGroups_DefaultGroupSizesOffMinimum(t *testing.T) {
	ctx := context.Background()

	newNode := func(name, cpu, mem string) *corev1.Node {
		return &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{}},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse(cpu),
					corev1.ResourceMemory: resource.MustParse(mem),
				},
			},
		}
	}

	// Big node first, small node last: first-node sizing would pick 64 cores;
	// minimum sizing must pick the 2-core / 4Gi box.
	nodes := []runtime.Object{
		newNode("big", "64", "256Gi"),
		newNode("small", "2", "4Gi"),
	}

	client := fake.NewClientset(nodes...)
	cfg := config.NodeAgentAutoscalerConfig{
		Enabled:          true,
		NodeGroupLabel:   "node.kubernetes.io/instance-type",
		DefaultNodeGroup: "default",
	}

	groups, err := NewNodeGrouper(client, cfg, "kubescape").GetNodeGroups(ctx)
	require.NoError(t, err)
	require.Len(t, groups, 1)

	g := groups[0]
	require.True(t, g.IsDefault)
	assert.Equal(t, 2, g.NodeCount)
	minCPU := resource.MustParse("2")
	minMem := resource.MustParse("4Gi")
	assert.Equal(t, minCPU.MilliValue(), g.AllocatableCPU.MilliValue(), "CPU should be the group minimum")
	assert.Equal(t, minMem.Value(), g.AllocatableMemory.Value(), "memory should be the group minimum")
}

func TestNodeGrouper_CalculateResources(t *testing.T) {
	cfg := config.NodeAgentAutoscalerConfig{
		ResourcePercentages: config.NodeAgentAutoscalerResourcePercentages{
			RequestCPU:    2,
			RequestMemory: 2,
			LimitCPU:      5,
			LimitMemory:   5,
		},
		MinResources: config.NodeAgentAutoscalerResourceBounds{
			CPU:    "100m",
			Memory: "180Mi",
		},
		MaxResources: config.NodeAgentAutoscalerResourceBounds{
			CPU:    "2000m",
			Memory: "4Gi",
		},
	}

	ng := NewNodeGrouper(nil, cfg, "kubescape")

	group := NodeGroup{
		LabelValue:        "m5.large",
		SanitizedName:     "m5-large",
		AllocatableCPU:    resource.MustParse("4"),
		AllocatableMemory: resource.MustParse("16Gi"),
		NodeCount:         1,
	}

	resources, err := ng.CalculateResources(group)
	require.NoError(t, err)

	// 2% of 4 cores = 80m, but min is 100m
	assert.Equal(t, int64(100), resources.Requests.CPU.MilliValue())
	// 5% of 4 cores = 200m
	assert.Equal(t, int64(200), resources.Limits.CPU.MilliValue())

	// 2% of 16Gi memory = ~327Mi, which is above min 180Mi
	// 5% of 16Gi memory = ~819Mi
}

func TestIsNodeReady(t *testing.T) {
	tests := []struct {
		name     string
		node     *corev1.Node
		expected bool
	}{
		{
			name: "ready node",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
					},
				},
			},
			expected: true,
		},
		{
			name: "not ready node",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{Type: corev1.NodeReady, Status: corev1.ConditionFalse},
					},
				},
			},
			expected: false,
		},
		{
			name: "no ready condition",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNodeReady(tt.node)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAutoscaler_GetManagedDaemonSets(t *testing.T) {
	ctx := context.Background()

	// Create test DaemonSets
	daemonSets := []runtime.Object{
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "node-agent-m5-large",
				Namespace: "kubescape",
				Labels: map[string]string{
					ManagedByLabel:    ManagedByValue,
					NodeGroupLabelKey: "m5.large",
				},
			},
		},
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "node-agent-manual",
				Namespace: "kubescape",
				Labels:    map[string]string{}, // Not managed by autoscaler
			},
		},
	}

	client := fake.NewClientset(daemonSets...)

	autoscaler := &Autoscaler{
		client:    client,
		namespace: "kubescape",
	}

	managedDS, err := autoscaler.getManagedDaemonSets(ctx)
	require.NoError(t, err)
	assert.Len(t, managedDS, 1)
	assert.Equal(t, "node-agent-m5-large", managedDS[0].Name)
}

func TestGenerateDaemonSetName(t *testing.T) {
	group := NodeGroup{
		LabelValue:    "m5.large",
		SanitizedName: "m5-large",
	}

	name := GenerateDaemonSetName(group)
	assert.Equal(t, "node-agent-m5-large", name)
}

func TestNewAutoscaler(t *testing.T) {
	client := fake.NewClientset()
	cfg := config.NodeAgentAutoscalerConfig{
		Enabled:              true,
		GoMemLimitPercentage: 0.8,
		NodeGroupLabel:       "node.kubernetes.io/instance-type",
		ReconcileInterval:    5 * time.Minute,
		TemplatePath:         "/tmp/nonexistent-template.yaml", // Will fail
	}

	// Should fail because template doesn't exist
	_, err := NewAutoscaler(client, cfg, "kubescape", "operator")
	assert.Error(t, err)
}

// reconcileTestTemplate is a minimal DaemonSet template exercising both targeting
// branches, used by the Reconcile test.
const reconcileTestTemplate = `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: "{{ .Name }}"
  namespace: kubescape
  labels:
    kubescape.io/managed-by: operator-autoscaler
    kubescape.io/node-group: "{{ .NodeGroupLabel }}"
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: node-agent
  template:
    metadata:
      labels:
        app.kubernetes.io/name: node-agent
    spec:
      containers:
      - name: node-agent
        image: "quay.io/kubescape/node-agent:test"
        resources:
          requests:
            cpu: "{{ .Resources.Requests.CPU }}"
            memory: "{{ .Resources.Requests.Memory }}"
          limits:
            cpu: "{{ .Resources.Limits.CPU }}"
            memory: "{{ .Resources.Limits.Memory }}"
{{- if .IsDefaultGroup }}
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: {{ .NodeGroupLabelKey }}
                operator: DoesNotExist
      nodeSelector:
        kubernetes.io/os: linux
{{- else }}
      nodeSelector:
        kubernetes.io/os: linux
        {{ .NodeGroupLabelKey }}: "{{ .NodeGroupLabel }}"
{{- end }}
`

// TestAutoscaler_Reconcile_CreatesPerGroupAndDeletesOrphans verifies that Reconcile
// creates one DaemonSet per node group (keyed by the unique DaemonSet name) and
// removes managed DaemonSets whose group no longer exists.
func TestAutoscaler_Reconcile_CreatesPerGroupAndDeletesOrphans(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "daemonset-template.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(reconcileTestTemplate), 0644))

	newNode := func(name string, labels map[string]string) *corev1.Node {
		return &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi"),
				},
			},
		}
	}

	// A stale managed DaemonSet whose group no longer exists -> must be deleted.
	orphan := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "node-agent-gone",
			Namespace: "kubescape",
			Labels:    map[string]string{ManagedByLabel: ManagedByValue, NodeGroupLabelKey: "gone"},
		},
	}

	client := fake.NewClientset(
		newNode("labelled", map[string]string{"node.kubernetes.io/instance-type": "m5.large"}),
		newNode("no-label", map[string]string{}),
		orphan,
	)

	cfg := config.NodeAgentAutoscalerConfig{
		Enabled:              true,
		NodeGroupLabel:       "node.kubernetes.io/instance-type",
		DefaultNodeGroup:     "default",
		GoMemLimitPercentage: 0.8,
		ResourcePercentages:  config.NodeAgentAutoscalerResourcePercentages{RequestCPU: 2, RequestMemory: 2, LimitCPU: 5, LimitMemory: 5},
		MinResources:         config.NodeAgentAutoscalerResourceBounds{CPU: "100m", Memory: "180Mi"},
		MaxResources:         config.NodeAgentAutoscalerResourceBounds{CPU: "2000m", Memory: "4Gi"},
		ReconcileInterval:    5 * time.Minute,
		TemplatePath:         templatePath,
	}

	a, err := NewAutoscaler(client, cfg, "kubescape", "")
	require.NoError(t, err)

	require.NoError(t, a.Reconcile(ctx))

	list, err := client.AppsV1().DaemonSets("kubescape").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)

	names := map[string]bool{}
	for _, ds := range list.Items {
		names[ds.Name] = true
	}
	assert.True(t, names["node-agent-m5-large"], "labelled group DaemonSet should exist")
	assert.True(t, names["node-agent-default"], "default group DaemonSet should exist")
	assert.False(t, names["node-agent-gone"], "orphaned DaemonSet should be deleted")
}
