package nodeagentautoscaler

import (
	"context"
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

	client := fake.NewSimpleClientset(nodes...)

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

	client := fake.NewSimpleClientset(nodes...)

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

	client := fake.NewSimpleClientset(daemonSets...)

	autoscaler := &Autoscaler{
		client:    client,
		namespace: "kubescape",
	}

	managedDS, err := autoscaler.getManagedDaemonSets(ctx)
	require.NoError(t, err)
	assert.Len(t, managedDS, 1)
	assert.Equal(t, "node-agent-m5-large", managedDS[0].Name)
}

func TestAutoscaler_DaemonSetNeedsUpdate(t *testing.T) {
	autoscaler := &Autoscaler{}

	existingDS := &appsv1.DaemonSet{
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "node-agent",
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("180Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("500m"),
									corev1.ResourceMemory: resource.MustParse("1Gi"),
								},
							},
						},
					},
					NodeSelector: map[string]string{
						"node.kubernetes.io/instance-type": "m5.large",
					},
				},
			},
		},
	}

	// Same resources - no update needed
	sameDS := existingDS.DeepCopy()
	assert.False(t, autoscaler.daemonSetNeedsUpdate(existingDS, sameDS))

	// Different resources - update needed
	differentResourcesDS := existingDS.DeepCopy()
	differentResourcesDS.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceCPU] = resource.MustParse("200m")
	assert.True(t, autoscaler.daemonSetNeedsUpdate(existingDS, differentResourcesDS))

	// Different nodeSelector - update needed
	differentSelectorDS := existingDS.DeepCopy()
	differentSelectorDS.Spec.Template.Spec.NodeSelector["node.kubernetes.io/instance-type"] = "m5.xlarge"
	assert.True(t, autoscaler.daemonSetNeedsUpdate(existingDS, differentSelectorDS))
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
	client := fake.NewSimpleClientset()
	cfg := config.NodeAgentAutoscalerConfig{
		Enabled:           true,
		NodeGroupLabel:    "node.kubernetes.io/instance-type",
		ReconcileInterval: 5 * time.Minute,
		TemplatePath:      "/tmp/nonexistent-template.yaml", // Will fail
	}

	// Should fail because template doesn't exist
	_, err := NewAutoscaler(client, cfg, "kubescape")
	assert.Error(t, err)
}

