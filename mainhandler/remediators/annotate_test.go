package remediators

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// capturePatchDryRun installs a pass-through reactor that records the DryRun
// option of the next patch on the given resource. The fake clientset's tracker
// ignores server-side dry-run (it always persists), so the only reliable way to
// assert dry-run behaviour is to inspect the option actually sent on the wire.
func capturePatchDryRun(client *k8sfake.Clientset, resource string, out *[]string) {
	client.PrependReactor("patch", resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
		*out = action.(clienttesting.PatchActionImpl).PatchOptions.DryRun
		return false, nil, nil // not handled: let the default tracker apply the patch
	})
}

func annotatedDeployment(ns, name string, annotations map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: annotations},
	}
}

func TestAnnotatePlan(t *testing.T) {
	r := NewAnnotateRemediator(k8sfake.NewClientset())
	plan, err := r.Plan(context.Background(), Request{
		Target:     Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Reason:     "C-0016",
		FindingRef: "workloadconfigurationscansummaries/payments/api",
	})
	require.NoError(t, err)
	assert.Equal(t, string(apis.OperatorActionAnnotate), plan.Action)
	assert.Equal(t, "Deployment/payments/api", plan.Target.String())

	var parsed struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal([]byte(plan.Patch), &parsed))
	assert.Equal(t, "true", parsed.Metadata.Annotations[AnnotationRemediated])
	assert.Equal(t, "C-0016", parsed.Metadata.Annotations[AnnotationReason])
	assert.Equal(t, "workloadconfigurationscansummaries/payments/api", parsed.Metadata.Annotations[AnnotationFindingRef])
}

func TestAnnotatePlanRequiresKindAndName(t *testing.T) {
	r := NewAnnotateRemediator(k8sfake.NewClientset())
	_, err := r.Plan(context.Background(), Request{Target: Target{Name: "api"}})
	assert.Error(t, err)
	_, err = r.Plan(context.Background(), Request{Target: Target{Kind: "Deployment"}})
	assert.Error(t, err)
}

func TestAnnotateApplyConfirm(t *testing.T) {
	client := k8sfake.NewClientset(annotatedDeployment("payments", "api", nil))
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)

	r := NewAnnotateRemediator(client)
	plan, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"}, Reason: "C-0016"})
	require.NoError(t, err)

	res, err := r.Apply(context.Background(), plan, false)
	require.NoError(t, err)
	assert.False(t, res.DryRun)
	assert.True(t, res.Applied)
	assert.Empty(t, dryRun, "a confirmed apply must not request server-side dry-run")

	got, err := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "true", got.Annotations[AnnotationRemediated])
	assert.Equal(t, "C-0016", got.Annotations[AnnotationReason])
}

func TestAnnotateApplyDryRun(t *testing.T) {
	client := k8sfake.NewClientset(annotatedDeployment("payments", "api", nil))
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)

	r := NewAnnotateRemediator(client)
	plan, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"}})
	require.NoError(t, err)

	res, err := r.Apply(context.Background(), plan, true)
	require.NoError(t, err)
	assert.True(t, res.DryRun)
	assert.False(t, res.Applied)
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "a dry-run apply must request server-side dry-run")
}

func TestAnnotateApplyPod(t *testing.T) {
	client := k8sfake.NewClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api-0"}})
	r := NewAnnotateRemediator(client)
	plan, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Pod", Namespace: "payments", Name: "api-0"}})
	require.NoError(t, err)
	_, err = r.Apply(context.Background(), plan, false)
	require.NoError(t, err)

	got, err := client.CoreV1().Pods("payments").Get(context.Background(), "api-0", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "true", got.Annotations[AnnotationRemediated])
}

func TestAnnotateApplyUnsupportedKind(t *testing.T) {
	r := NewAnnotateRemediator(k8sfake.NewClientset())
	plan, err := r.Plan(context.Background(), Request{Target: Target{Kind: "Service", Namespace: "payments", Name: "api"}})
	require.NoError(t, err) // Plan validates presence, not supportedness
	_, err = r.Apply(context.Background(), plan, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported target kind")
}

func TestAnnotateRevert(t *testing.T) {
	client := k8sfake.NewClientset(annotatedDeployment("payments", "api", map[string]string{
		AnnotationRemediated: "true",
		AnnotationReason:     "C-0016",
		"unrelated":          "keep-me",
	}))
	r := NewAnnotateRemediator(client)

	res, err := r.Revert(context.Background(), Target{Kind: "Deployment", Namespace: "payments", Name: "api"}, false)
	require.NoError(t, err)
	assert.True(t, res.Applied)
	assert.False(t, res.DryRun)
	assert.Equal(t, string(apis.OperatorActionRevert), res.Action)

	got, err := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, err)
	_, ok := got.Annotations[AnnotationRemediated]
	assert.False(t, ok, "remediation marker must be removed")
	_, ok = got.Annotations[AnnotationReason]
	assert.False(t, ok, "reason annotation must be removed")
	assert.Equal(t, "keep-me", got.Annotations["unrelated"], "unrelated annotations must be preserved")
}

// revert runs on every target regardless of which action was applied, so a
// workload that was never annotated must be reported as a no-op ("nothing to
// revert", Applied=false) instead of claiming annotations were removed — and it
// must not issue a patch.
func TestAnnotateRevertNoAnnotationsIsNoop(t *testing.T) {
	client := k8sfake.NewClientset(annotatedDeployment("payments", "api", map[string]string{"unrelated": "keep-me"}))
	patched := false
	client.PrependReactor("patch", "deployments", func(action clienttesting.Action) (bool, runtime.Object, error) {
		patched = true
		return false, nil, nil
	})
	r := NewAnnotateRemediator(client)

	res, err := r.Revert(context.Background(), Target{Kind: "Deployment", Namespace: "payments", Name: "api"}, false)
	require.NoError(t, err)
	assert.False(t, res.Applied, "nothing to revert")
	assert.Contains(t, res.Description, "nothing to revert")
	assert.False(t, patched, "revert must not patch a workload with no kubescape annotations")
}

// A dry-run revert must request server-side dry-run and never persist, mirroring
// Apply — so the safe-by-default contract holds for revert too.
func TestAnnotateRevertDryRun(t *testing.T) {
	client := k8sfake.NewClientset(annotatedDeployment("payments", "api", map[string]string{
		AnnotationRemediated: "true",
		AnnotationReason:     "C-0016",
	}))
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)
	r := NewAnnotateRemediator(client)

	res, err := r.Revert(context.Background(), Target{Kind: "Deployment", Namespace: "payments", Name: "api"}, true)
	require.NoError(t, err)
	assert.True(t, res.DryRun)
	assert.False(t, res.Applied)
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "a dry-run revert must request server-side dry-run")
}
