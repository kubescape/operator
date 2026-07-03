package remediators

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// captureCreateDryRun records the DryRun option of the next create on the given
// resource; the fake tracker ignores server-side dry-run (it always persists),
// so the only reliable assertion is the option actually sent on the wire.
func captureCreateDryRun(client *k8sfake.Clientset, resource string, out *[]string) {
	client.PrependReactor("create", resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
		*out = action.(clienttesting.CreateActionImpl).CreateOptions.DryRun
		return false, nil, nil // not handled: let the default tracker apply
	})
}

func captureDeleteDryRun(client *k8sfake.Clientset, resource string, out *[]string) {
	client.PrependReactor("delete", resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
		*out = action.(clienttesting.DeleteActionImpl).DeleteOptions.DryRun
		return false, nil, nil
	})
}

func deploymentWithSelector(ns, name string, selector map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: selector}},
	}
}

func TestQuarantinePlan(t *testing.T) {
	client := k8sfake.NewClientset(deploymentWithSelector("payments", "api", map[string]string{"app": "api"}))
	r := NewQuarantineRemediator(client)
	plan, err := r.Plan(context.Background(), Request{
		Target:     Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Reason:     "C-0016",
		FindingRef: "workloadconfigurationscansummaries/payments/api",
	})
	require.NoError(t, err)
	assert.Equal(t, string(apis.OperatorActionQuarantine), plan.Action)
	assert.Equal(t, "Deployment/payments/api", plan.Target.String())

	np := decodeNP(t, plan.Patch)
	assert.Equal(t, "kubescape-quarantine-deployment-api", np.Name)
	assert.Equal(t, "payments", np.Namespace)
	assert.Equal(t, "true", np.Labels[LabelQuarantine])
	assert.Equal(t, "Deployment/payments/api", np.Annotations[AnnotationQuarantineTarget])
	assert.Equal(t, "C-0016", np.Annotations[AnnotationReason])
	assert.Equal(t, map[string]string{"app": "api"}, np.Spec.PodSelector.MatchLabels)
	assert.ElementsMatch(t, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}, np.Spec.PolicyTypes)
	assert.Empty(t, np.Spec.Ingress, "deny-all means no ingress rules")
	assert.Empty(t, np.Spec.Egress, "deny-all means no egress rules")
}

// A workload using set-based selectors (matchExpressions) must have that full
// selector carried into the NetworkPolicy, not silently dropped.
func TestQuarantinePlanPreservesMatchExpressions(t *testing.T) {
	expr := []metav1.LabelSelectorRequirement{{
		Key:      "tier",
		Operator: metav1.LabelSelectorOpIn,
		Values:   []string{"backend", "api"},
	}}
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"},
		Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{
			MatchLabels:      map[string]string{"app": "api"},
			MatchExpressions: expr,
		}},
	}
	r := NewQuarantineRemediator(k8sfake.NewClientset(deploy))
	plan, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"}})
	require.NoError(t, err)

	np := decodeNP(t, plan.Patch)
	assert.Equal(t, map[string]string{"app": "api"}, np.Spec.PodSelector.MatchLabels)
	assert.Equal(t, expr, np.Spec.PodSelector.MatchExpressions, "set-based selector requirements must be preserved")
}

func TestQuarantinePlanRequiresSelectorLabels(t *testing.T) {
	client := k8sfake.NewClientset(deploymentWithSelector("payments", "api", nil))
	r := NewQuarantineRemediator(client)
	_, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no pod selector labels")
}

func TestQuarantinePlanUnsupportedKind(t *testing.T) {
	r := NewQuarantineRemediator(k8sfake.NewClientset())
	_, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Service", Namespace: "payments", Name: "api"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported target kind")
}

func TestQuarantineApplyConfirm(t *testing.T) {
	client := k8sfake.NewClientset(deploymentWithSelector("payments", "api", map[string]string{"app": "api"}))
	var dryRun []string
	captureCreateDryRun(client, "networkpolicies", &dryRun)

	r := NewQuarantineRemediator(client)
	plan, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"}})
	require.NoError(t, err)

	res, err := r.Apply(context.Background(), plan, false)
	require.NoError(t, err)
	assert.False(t, res.DryRun)
	assert.True(t, res.Applied)
	assert.Empty(t, dryRun, "a confirmed apply must not request server-side dry-run")

	got, err := client.NetworkingV1().NetworkPolicies("payments").Get(context.Background(), "kubescape-quarantine-deployment-api", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "api"}, got.Spec.PodSelector.MatchLabels)
	assert.ElementsMatch(t, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}, got.Spec.PolicyTypes)
}

func TestQuarantineApplyDryRun(t *testing.T) {
	client := k8sfake.NewClientset(deploymentWithSelector("payments", "api", map[string]string{"app": "api"}))
	var dryRun []string
	captureCreateDryRun(client, "networkpolicies", &dryRun)

	r := NewQuarantineRemediator(client)
	plan, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"}})
	require.NoError(t, err)

	res, err := r.Apply(context.Background(), plan, true)
	require.NoError(t, err)
	assert.True(t, res.DryRun)
	assert.False(t, res.Applied)
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "a dry-run apply must request server-side dry-run")
}

func TestQuarantineApplyPodUsesPodLabels(t *testing.T) {
	client := k8sfake.NewClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api-0", Labels: map[string]string{"app": "api", "pod-template-hash": "abc"}},
	})
	r := NewQuarantineRemediator(client)
	plan, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Pod", Namespace: "payments", Name: "api-0"}})
	require.NoError(t, err)
	_, err = r.Apply(context.Background(), plan, false)
	require.NoError(t, err)

	got, err := client.NetworkingV1().NetworkPolicies("payments").Get(context.Background(), "kubescape-quarantine-pod-api-0", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "api", "pod-template-hash": "abc"}, got.Spec.PodSelector.MatchLabels)
}

// A second quarantine on an already-isolated workload must succeed (idempotent).
func TestQuarantineApplyAlreadyExists(t *testing.T) {
	client := k8sfake.NewClientset(deploymentWithSelector("payments", "api", map[string]string{"app": "api"}))
	r := NewQuarantineRemediator(client)
	plan, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"}})
	require.NoError(t, err)

	_, err = r.Apply(context.Background(), plan, false)
	require.NoError(t, err)
	res, err := r.Apply(context.Background(), plan, false)
	require.NoError(t, err)
	assert.True(t, res.Applied)
}

// Re-quarantining after the workload's selector changed must reconcile the
// existing policy to the new selector, not leave the stale one in place (which
// would report success while the running pods stay unisolated).
func TestQuarantineApplyReconcilesSelectorDrift(t *testing.T) {
	client := k8sfake.NewClientset(deploymentWithSelector("payments", "api", map[string]string{"app": "api"}))
	r := NewQuarantineRemediator(client)

	plan, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"}})
	require.NoError(t, err)
	_, err = r.Apply(context.Background(), plan, false)
	require.NoError(t, err)

	// The workload is edited/redeployed with a new selector.
	_, err = client.AppsV1().Deployments("payments").Update(context.Background(),
		deploymentWithSelector("payments", "api", map[string]string{"app": "api", "track": "blue"}), metav1.UpdateOptions{})
	require.NoError(t, err)

	plan, err = r.Plan(context.Background(), Request{Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"}})
	require.NoError(t, err)
	res, err := r.Apply(context.Background(), plan, false)
	require.NoError(t, err)
	assert.True(t, res.Applied)

	got, err := client.NetworkingV1().NetworkPolicies("payments").Get(context.Background(), "kubescape-quarantine-deployment-api", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "api", "track": "blue"}, got.Spec.PodSelector.MatchLabels,
		"an already-existing policy must be reconciled to the current selector")
}

// Reconciling an already-correct policy must issue the update as a server-side
// dry-run when dryRun is set, honoring the safe-by-default contract.
func TestQuarantineApplyReconcileHonorsDryRun(t *testing.T) {
	client := k8sfake.NewClientset(deploymentWithSelector("payments", "api", map[string]string{"app": "api"}))
	r := NewQuarantineRemediator(client)

	plan, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"}})
	require.NoError(t, err)
	_, err = r.Apply(context.Background(), plan, false)
	require.NoError(t, err)

	_, err = client.AppsV1().Deployments("payments").Update(context.Background(),
		deploymentWithSelector("payments", "api", map[string]string{"app": "api", "track": "blue"}), metav1.UpdateOptions{})
	require.NoError(t, err)

	var dryRun []string
	client.PrependReactor("update", "networkpolicies", func(action clienttesting.Action) (bool, runtime.Object, error) {
		dryRun = action.(clienttesting.UpdateActionImpl).UpdateOptions.DryRun
		return false, nil, nil
	})

	plan, err = r.Plan(context.Background(), Request{Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"}})
	require.NoError(t, err)
	res, err := r.Apply(context.Background(), plan, true)
	require.NoError(t, err)
	assert.True(t, res.DryRun)
	assert.False(t, res.Applied)
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "a dry-run reconcile must request server-side dry-run")
}

func TestQuarantineRevert(t *testing.T) {
	existing := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "kubescape-quarantine-deployment-api", Labels: map[string]string{LabelQuarantine: "true"}},
	}
	client := k8sfake.NewClientset(existing)
	r := NewQuarantineRemediator(client)

	res, err := r.Revert(context.Background(), Target{Kind: "Deployment", Namespace: "payments", Name: "api"}, false)
	require.NoError(t, err)
	assert.True(t, res.Applied)
	assert.Equal(t, string(apis.OperatorActionRevert), res.Action)

	_, err = client.NetworkingV1().NetworkPolicies("payments").Get(context.Background(), "kubescape-quarantine-deployment-api", metav1.GetOptions{})
	assert.Error(t, err, "the quarantine NetworkPolicy must be deleted")
}

// Reverting a target that was never quarantined is a no-op success.
func TestQuarantineRevertNotFound(t *testing.T) {
	r := NewQuarantineRemediator(k8sfake.NewClientset())
	res, err := r.Revert(context.Background(), Target{Kind: "Deployment", Namespace: "payments", Name: "api"}, false)
	require.NoError(t, err)
	assert.False(t, res.Applied, "nothing to revert")
	assert.Contains(t, res.Description, "nothing to revert")
}

func TestQuarantineRevertDryRun(t *testing.T) {
	existing := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "kubescape-quarantine-deployment-api"},
	}
	client := k8sfake.NewClientset(existing)
	var dryRun []string
	captureDeleteDryRun(client, "networkpolicies", &dryRun)
	r := NewQuarantineRemediator(client)

	res, err := r.Revert(context.Background(), Target{Kind: "Deployment", Namespace: "payments", Name: "api"}, true)
	require.NoError(t, err)
	assert.True(t, res.DryRun)
	assert.False(t, res.Applied)
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "a dry-run revert must request server-side dry-run")
}

func TestQuarantineNPNameTruncation(t *testing.T) {
	long := strings.Repeat("a", 300)
	name := quarantineNPName(Target{Kind: "Deployment", Namespace: "payments", Name: long})
	assert.LessOrEqual(t, len(name), maxNameLen)
	assert.True(t, strings.HasPrefix(name, quarantineNPPrefix))
}

// Different kinds sharing a name must not collide on the same NetworkPolicy,
// otherwise reverting one target would delete another's policy.
func TestQuarantineNPNameUniquePerKind(t *testing.T) {
	deploy := quarantineNPName(Target{Kind: "Deployment", Namespace: "payments", Name: "api"})
	sts := quarantineNPName(Target{Kind: "StatefulSet", Namespace: "payments", Name: "api"})
	assert.NotEqual(t, deploy, sts)
	assert.Equal(t, "kubescape-quarantine-deployment-api", deploy)
}

func decodeNP(t *testing.T, body string) *networkingv1.NetworkPolicy {
	t.Helper()
	var np networkingv1.NetworkPolicy
	require.NoError(t, json.Unmarshal([]byte(body), &np))
	return &np
}
