package remediators

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func podForPatch(ns, name string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
}

func TestPatchPlan_ValidStrategicMergePatch(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	plan, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"spec":{"template":{"spec":{"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}}}}}}`,
	})
	require.NoError(t, err)
	assert.Equal(t, string(OperatorActionPatch), plan.Action)
	assert.Equal(t, "Deployment/payments/api", plan.Target.String())
	assert.Equal(t, string(types.StrategicMergePatchType), plan.PatchType)
	assert.JSONEq(t, `{"spec":{"template":{"spec":{"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}}}}}}`, plan.Patch)
}

func TestPatchPlan_YAMLPatchIsCanonicalizedToJSON(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	yamlPatch := "spec:\n  template:\n    spec:\n      securityContext:\n        seccompProfile:\n          type: RuntimeDefault\n"
	plan, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Pod", Namespace: "payments", Name: "api"},
		Patch:  yamlPatch,
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"spec":{"template":{"spec":{"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}}}}}}`, plan.Patch)
}

func TestPatchPlan_MergePatchType(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	plan, err := r.Plan(context.Background(), Request{
		Target:    Target{Kind: "StatefulSet", Namespace: "payments", Name: "db"},
		Patch:     `{"metadata":{"labels":{"foo":"bar"}}}`,
		PatchType: types.MergePatchType,
	})
	require.NoError(t, err)
	assert.Equal(t, string(types.MergePatchType), plan.PatchType)
}

func TestPatchPlan_InvalidJSON(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	_, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{not valid json or yaml: [`,
	})
	require.Error(t, err)
}

func TestPatchPlan_EmptyPatch(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	_, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  "",
	})
	require.Error(t, err)
}

func TestPatchPlan_PatchMustBeObjectNotArray(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	_, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `[{"op":"replace","path":"/spec","value":{}}]`,
	})
	require.Error(t, err, "JSON Patch (RFC 6902) arrays are not supported by this action")
}

func TestPatchPlan_UnsupportedKind(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	_, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Node", Name: "node-1"},
		Patch:  `{"metadata":{"labels":{"foo":"bar"}}}`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported target kind")
}

func TestPatchPlan_UnsupportedPatchType(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	_, err := r.Plan(context.Background(), Request{
		Target:    Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:     `{"metadata":{"labels":{"foo":"bar"}}}`,
		PatchType: types.JSONPatchType,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported patchType")
}

func TestPatchPlan_RequiresKindAndName(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	_, err := r.Plan(context.Background(), Request{Target: Target{Name: "api"}, Patch: `{}`})
	require.Error(t, err)
}

func TestPatchApply_DryRunDoesNotPersist(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)

	r := NewPatchRemediator(client)
	plan, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"metadata":{"labels":{"foo":"bar"}}}`,
	})
	require.NoError(t, err)

	result, err := r.Apply(context.Background(), plan, true)
	require.NoError(t, err)
	assert.True(t, result.DryRun)
	assert.False(t, result.Applied)
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "a dry-run apply must request server-side dry-run")
}

func TestPatchApply_ConfirmedWritesDeployment(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	r := NewPatchRemediator(client)
	plan, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"metadata":{"labels":{"foo":"bar"}}}`,
	})
	require.NoError(t, err)

	result, err := r.Apply(context.Background(), plan, false)
	require.NoError(t, err)
	assert.True(t, result.Applied)
	assert.False(t, result.DryRun)

	got, err := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "bar", got.Labels["foo"])
}

func TestPatchApply_ConfirmedWritesPod(t *testing.T) {
	client := k8sfake.NewClientset(podForPatch("payments", "worker"))
	r := NewPatchRemediator(client)
	plan, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Pod", Namespace: "payments", Name: "worker"},
		Patch:  `{"metadata":{"labels":{"foo":"bar"}}}`,
	})
	require.NoError(t, err)

	result, err := r.Apply(context.Background(), plan, false)
	require.NoError(t, err)
	assert.True(t, result.Applied)

	got, err := client.CoreV1().Pods("payments").Get(context.Background(), "worker", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "bar", got.Labels["foo"])
}

func TestPatchApply_UnsupportedKindFails(t *testing.T) {
	client := k8sfake.NewClientset()
	r := NewPatchRemediator(client)
	_, err := r.Apply(context.Background(), Plan{
		Target: Target{Kind: "Node", Name: "node-1"},
		Patch:  `{"metadata":{"labels":{"foo":"bar"}}}`,
	}, false)
	require.Error(t, err)
}

func TestPatchRevert_ReturnsInformativeError(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	_, err := r.Revert(context.Background(), Target{Kind: "Deployment", Namespace: "payments", Name: "api"}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be automatically reverted")
}

func TestPatchApply_RecordsPatchInResultForAudit(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	r := NewPatchRemediator(client)
	plan, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"metadata":{"labels":{"foo":"bar"}}}`,
	})
	require.NoError(t, err)

	result, err := r.Apply(context.Background(), plan, false)
	require.NoError(t, err)
	assert.JSONEq(t, `{"metadata":{"labels":{"foo":"bar"}}}`, result.Patch, "the applied patch body must be recorded on Result for the audit trail")
	assert.Equal(t, string(types.StrategicMergePatchType), result.PatchType)
}

func TestPatchPlan_RejectsNullPatch(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	_, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  "null",
	})
	require.Error(t, err)
}

func TestPatchPlan_RejectsEmptyObjectPatch(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	_, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  "{}",
	})
	require.Error(t, err)
}

func TestPatchPlan_RejectsOversizedPatch(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	huge := `{"metadata":{"labels":{"foo":"` + strings.Repeat("a", maxPatchBytes) + `"}}}`
	_, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  huge,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

// Escalation-relevant fields must be rejected regardless of patch type, on
// every supported workload kind: they would let a caller convert this action's
// cluster-wide patch RBAC into node or cluster compromise.
func TestPatchPlan_RejectsEscalationFields(t *testing.T) {
	cases := []struct {
		name  string
		kind  string
		patch string
	}{
		{"hostNetwork on Deployment", "Deployment", `{"spec":{"template":{"spec":{"hostNetwork":true}}}}`},
		{"hostPID on StatefulSet", "StatefulSet", `{"spec":{"template":{"spec":{"hostPID":true}}}}`},
		{"hostIPC on DaemonSet", "DaemonSet", `{"spec":{"template":{"spec":{"hostIPC":true}}}}`},
		{"serviceAccountName on Deployment", "Deployment", `{"spec":{"template":{"spec":{"serviceAccountName":"cluster-admin-sa"}}}}`},
		{"volumes (hostPath) on Deployment", "Deployment", `{"spec":{"template":{"spec":{"volumes":[{"name":"h","hostPath":{"path":"/"}}]}}}}`},
		{"nodeName on Deployment", "Deployment", `{"spec":{"template":{"spec":{"nodeName":"node-1"}}}}`},
		{"hostNetwork on Pod", "Pod", `{"spec":{"hostNetwork":true}}`},
		{"serviceAccountName on Pod", "Pod", `{"spec":{"serviceAccountName":"cluster-admin-sa"}}`},
		{"ownerReferences", "Deployment", `{"metadata":{"ownerReferences":[{"apiVersion":"v1","kind":"Node","name":"n","uid":"x"}]}}`},
		{"finalizers", "Deployment", `{"metadata":{"finalizers":["evil.example.com/hold"]}}`},
		{"container privileged", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"privileged":true}}]}}}}`},
		{"container allowPrivilegeEscalation", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"allowPrivilegeEscalation":true}}]}}}}`},
		{"container added capabilities", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"add":["SYS_ADMIN"]}}}]}}}}`},
		{"container image change", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","image":"attacker/img"}]}}}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewPatchRemediator(k8sfake.NewClientset())
			_, err := r.Plan(context.Background(), Request{
				Target: Target{Kind: c.kind, Namespace: "payments", Name: "api"},
				Patch:  c.patch,
			})
			require.Error(t, err, "escalation-relevant field must be rejected")
			assert.Contains(t, err.Error(), "not allowed")
		})
	}
}

// A patch touching only non-escalation-relevant fields must still be accepted
// — the denylist must not be so broad it blocks the feature's own use case.
func TestPatchPlan_AllowsNonEscalationFields(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	plan, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"seccompProfile":{"type":"RuntimeDefault"}}}]}}}}`,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, plan.Patch)
}

func TestPatchApply_RejectsEscalationFieldsEvenWithHandcraftedPlan(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	r := NewPatchRemediator(client)
	// A Plan built out of band (bypassing Plan()) must still be rejected by
	// Apply — validation belongs at the boundary that performs the write.
	_, err := r.Apply(context.Background(), Plan{
		Action: string(OperatorActionPatch),
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"spec":{"template":{"spec":{"hostNetwork":true}}}}`,
	}, false)
	require.Error(t, err)
}
