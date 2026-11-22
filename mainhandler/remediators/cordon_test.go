package remediators

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestCordonPlan_ValidNode(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Spec:       corev1.NodeSpec{Unschedulable: false},
	}
	client := k8sfake.NewClientset(node)
	r := NewCordonRemediator(client)

	req := Request{
		Target:     Target{Kind: "Node", Name: "worker-1"},
		Reason:     "suspicious-crypto-miner",
		FindingRef: "ioc-987",
	}

	plan, err := r.Plan(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, string(apis.OperatorActionCordon), plan.Action)
	assert.Equal(t, "Node", plan.Target.Kind)
	assert.Equal(t, "worker-1", plan.Target.Name)
	assert.Equal(t, `mark node "worker-1" unschedulable (cordon)`, plan.Description)
	assert.Equal(t, string(types.StrategicMergePatchType), plan.PatchType)
	assert.JSONEq(t, `{
		"metadata": {
			"annotations": {
				"kubescape.io/cordon": "true",
				"kubescape.io/remediated": "true",
				"kubescape.io/remediation-reason": "suspicious-crypto-miner",
				"kubescape.io/remediation-finding-ref": "ioc-987"
			}
		},
		"spec": {
			"unschedulable": true
		}
	}`, plan.Patch)
}

func TestCordonPlan_AlreadyUnschedulable(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Spec:       corev1.NodeSpec{Unschedulable: true},
	}
	client := k8sfake.NewClientset(node)
	r := NewCordonRemediator(client)

	req := Request{Target: Target{Kind: "Node", Name: "worker-1"}}
	plan, err := r.Plan(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, `node "worker-1" is already unschedulable (cordoned)`, plan.Description)
}

func TestCordonPlan_RejectsUnsupportedKind(t *testing.T) {
	r := NewCordonRemediator(k8sfake.NewClientset())
	_, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "default", Name: "api"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported target kind "Deployment"`)
}

func TestCordonPlan_RejectsMissingName(t *testing.T) {
	r := NewCordonRemediator(k8sfake.NewClientset())
	_, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Node"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target requires both kind and name")
}

func TestCordonApply_DryRunDoesNotMutate(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Spec:       corev1.NodeSpec{Unschedulable: false},
	}
	client := k8sfake.NewClientset(node)
	var dryRun []string
	capturePatchDryRun(client, "nodes", &dryRun)

	r := NewCordonRemediator(client)
	plan, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Node", Name: "worker-1"}})
	require.NoError(t, err)

	res, err := r.Apply(context.Background(), plan, true)
	require.NoError(t, err)
	assert.True(t, res.DryRun)
	assert.False(t, res.Applied)
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun)
}

func TestCordonApply_ConfirmMutatesNode(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Spec:       corev1.NodeSpec{Unschedulable: false},
	}
	client := k8sfake.NewClientset(node)
	r := NewCordonRemediator(client)

	plan, err := r.Plan(context.Background(), Request{
		Target:     Target{Kind: "Node", Name: "worker-1"},
		Reason:     "compromised-creds",
		FindingRef: "finding-42",
	})
	require.NoError(t, err)

	res, err := r.Apply(context.Background(), plan, false)
	require.NoError(t, err)
	assert.False(t, res.DryRun)
	assert.True(t, res.Applied)

	updated, err := client.CoreV1().Nodes().Get(context.Background(), "worker-1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.True(t, updated.Spec.Unschedulable)
	assert.Equal(t, "true", updated.Annotations[AnnotationCordon])
	assert.Equal(t, "true", updated.Annotations[AnnotationRemediated])
	assert.Equal(t, "compromised-creds", updated.Annotations[AnnotationReason])
	assert.Equal(t, "finding-42", updated.Annotations[AnnotationFindingRef])
}

func TestCordonRevert_DryRunDoesNotMutate(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "worker-1",
			Annotations: map[string]string{
				AnnotationCordon: "true",
			},
		},
		Spec: corev1.NodeSpec{Unschedulable: true},
	}
	client := k8sfake.NewClientset(node)
	var dryRun []string
	capturePatchDryRun(client, "nodes", &dryRun)

	r := NewCordonRemediator(client)
	res, err := r.Revert(context.Background(), Target{Kind: "Node", Name: "worker-1"}, true)
	require.NoError(t, err)
	assert.True(t, res.DryRun)
	assert.False(t, res.Applied)
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun)
}

func TestCordonRevert_RestoresSchedulableAndCleansAnnotations(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "worker-1",
			Annotations: map[string]string{
				AnnotationCordon:     "true",
				AnnotationRemediated: "true",
				AnnotationReason:     "test",
			},
		},
		Spec: corev1.NodeSpec{Unschedulable: true},
	}
	client := k8sfake.NewClientset(node)
	r := NewCordonRemediator(client)

	res, err := r.Revert(context.Background(), Target{Kind: "Node", Name: "worker-1"}, false)
	require.NoError(t, err)
	assert.False(t, res.DryRun)
	assert.True(t, res.Applied)
	assert.Equal(t, string(apis.OperatorActionRevert), res.Action)
	assert.Contains(t, res.Description, `marked node "worker-1" schedulable (uncordon)`)

	updated, err := client.CoreV1().Nodes().Get(context.Background(), "worker-1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.False(t, updated.Spec.Unschedulable)
	_, hasCordon := updated.Annotations[AnnotationCordon]
	assert.False(t, hasCordon)
	_, hasRemediated := updated.Annotations[AnnotationRemediated]
	assert.False(t, hasRemediated)
	_, hasReason := updated.Annotations[AnnotationReason]
	assert.False(t, hasReason)
}

func TestCordonRevert_RejectsUnsupportedKind(t *testing.T) {
	r := NewCordonRemediator(k8sfake.NewClientset())
	_, err := r.Revert(context.Background(), Target{Kind: "Pod", Namespace: "default", Name: "api"}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported target kind "Pod"`)
}

func TestCordonRevert_SkipsNodeNotCordonedByKubescape(t *testing.T) {
	// A node cordoned externally (e.g. by an administrator or maintenance script)
	// has unschedulable=true but does NOT have the kubescape.io/cordon annotation.
	// Revert must leave it unschedulable and report Applied=false.
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "worker-1",
			Annotations: map[string]string{
				"other-tool/cordon": "true",
			},
		},
		Spec: corev1.NodeSpec{Unschedulable: true},
	}
	client := k8sfake.NewClientset(node)
	r := NewCordonRemediator(client)

	res, err := r.Revert(context.Background(), Target{Kind: "Node", Name: "worker-1"}, false)
	require.NoError(t, err)
	assert.False(t, res.Applied)
	assert.Contains(t, res.Description, `node "worker-1" was not cordoned by kubescape; nothing to revert`)

	// The node must remain unschedulable
	got, err := client.CoreV1().Nodes().Get(context.Background(), "worker-1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.True(t, got.Spec.Unschedulable)
}

func TestCordonRevert_NodeWithoutAnnotations(t *testing.T) {
	// A node with nil annotations must also be safely treated as not cordoned by Kubescape.
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "worker-2",
		},
		Spec: corev1.NodeSpec{Unschedulable: true},
	}
	client := k8sfake.NewClientset(node)
	r := NewCordonRemediator(client)

	res, err := r.Revert(context.Background(), Target{Kind: "Node", Name: "worker-2"}, false)
	require.NoError(t, err)
	assert.False(t, res.Applied)
	assert.Contains(t, res.Description, `node "worker-2" was not cordoned by kubescape; nothing to revert`)

	got, err := client.CoreV1().Nodes().Get(context.Background(), "worker-2", metav1.GetOptions{})
	require.NoError(t, err)
	assert.True(t, got.Spec.Unschedulable)
}
