package remediators

import (
	"context"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/apis"
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
	assert.Equal(t, string(apis.OperatorActionPatch), plan.Action)
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
		// Under a JSON Merge Patch, null deletes the field rather than setting
		// it to null — so these null the entire securityContext (or a single
		// protected field within it) instead of setting a dangerous value, to
		// prove that route is rejected too, not just the "=true" route.
		{"container securityContext nulled entirely", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":null}]}}}}`},
		{"container allowPrivilegeEscalation nulled", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"allowPrivilegeEscalation":null}}]}}}}`},
		{"container capabilities nulled", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":null}}]}}}}`},
		{"pod seccompProfile Unconfined", "Deployment", `{"spec":{"template":{"spec":{"securityContext":{"seccompProfile":{"type":"Unconfined"}}}}}}`},
		{"pod seccompProfile nulled", "Deployment", `{"spec":{"template":{"spec":{"securityContext":{"seccompProfile":null}}}}}`},
		{"pod appArmorProfile Unconfined", "Deployment", `{"spec":{"template":{"spec":{"securityContext":{"appArmorProfile":{"type":"Unconfined"}}}}}}`},
		{"pod seccompProfile Unconfined on Pod", "Pod", `{"spec":{"securityContext":{"seccompProfile":{"type":"Unconfined"}}}}`},
		{"container seccompProfile Unconfined", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"seccompProfile":{"type":"Unconfined"}}}]}}}}`},
		{"container appArmorProfile Unconfined", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"appArmorProfile":{"type":"Unconfined"}}}]}}}}`},
		{"init container seccompProfile nulled", "Deployment", `{"spec":{"template":{"spec":{"initContainers":[{"name":"init","securityContext":{"seccompProfile":null}}]}}}}`},
		{"container capabilities.drop nulled", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":null}}}]}}}}`},
		{"container capabilities.drop emptied", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":[]}}}]}}}}`},
		{"init container capabilities.drop nulled", "Deployment", `{"spec":{"template":{"spec":{"initContainers":[{"name":"init","securityContext":{"capabilities":{"drop":null}}}]}}}}`},
		{"container runAsUser=0", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsUser":0}}]}}}}`},
		{"container runAsUser nulled", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsUser":null}}]}}}}`},
		{"container runAsGroup=0", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsGroup":0}}]}}}}`},
		{"container runAsGroup nulled", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsGroup":null}}]}}}}`},
		{"container seLinuxOptions", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"seLinuxOptions":{"type":"spc_t"}}}]}}}}`},
		{"init container seLinuxOptions", "Deployment", `{"spec":{"template":{"spec":{"initContainers":[{"name":"init","securityContext":{"seLinuxOptions":{"type":"spc_t"}}}]}}}}`},
		{"container runAsNonRoot=false", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsNonRoot":false}}]}}}}`},
		{"container runAsNonRoot nulled", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsNonRoot":null}}]}}}}`},
		// Strategic-merge directives ($patch: replace, $patch: delete, $retainKeys)
		// can replace or clear maps without naming protected fields, dropping
		// protections like runAsUser / runAsNonRoot. They must be rejected on
		// securityContext, container, and pod-spec maps.
		{"container securityContext $patch: replace", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"$patch":"replace","readOnlyRootFilesystem":true}}]}}}}`},
		{"container securityContext $patch: delete", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"$patch":"delete"}}]}}}}`},
		{"container securityContext $retainKeys", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"$retainKeys":["readOnlyRootFilesystem"]}}]}}}}`},
		{"container $patch: replace", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"$patch":"replace","name":"api"}]}}}}`},
		{"container $patch: delete", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"$patch":"delete","name":"api"}]}}}}`},
		{"container $retainKeys", "Deployment", `{"spec":{"template":{"spec":{"containers":[{"$retainKeys":["name"],"name":"api"}]}}}}`},
		{"pod spec $patch: replace on Deployment", "Deployment", `{"spec":{"template":{"spec":{"$patch":"replace","containers":[{"name":"api"}]}}}}`},
		{"pod spec $patch: delete on Deployment", "Deployment", `{"spec":{"template":{"spec":{"$patch":"delete"}}}}`},
		{"pod spec $retainKeys on Deployment", "Deployment", `{"spec":{"template":{"spec":{"$retainKeys":["containers"],"containers":[{"name":"api"}]}}}}`},
		{"pod spec $patch: replace on Pod", "Pod", `{"spec":{"$patch":"replace","containers":[{"name":"api"}]}}`},
		{"pod spec $patch: delete on Pod", "Pod", `{"spec":{"$patch":"delete"}}`},
		{"pod spec $retainKeys on Pod", "Pod", `{"spec":{"$retainKeys":["containers"],"containers":[{"name":"api"}]}}`},
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

// Setting a confining profile is what a seccomp or AppArmor remediation does, at
// either level, so RuntimeDefault and Localhost are still accepted.
func TestPatchPlan_AllowsConfiningProfiles(t *testing.T) {
	for _, patch := range []string{
		`{"spec":{"template":{"spec":{"securityContext":{"appArmorProfile":{"type":"RuntimeDefault"}}}}}}`,
		`{"spec":{"template":{"spec":{"securityContext":{"seccompProfile":{"type":"Localhost","localhostProfile":"profiles/audit.json"}}}}}}`,
		`{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"appArmorProfile":{"type":"Localhost","localhostProfile":"k8s-apparmor-example"}}}]}}}}`,
	} {
		r := NewPatchRemediator(k8sfake.NewClientset())
		plan, err := r.Plan(context.Background(), Request{
			Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
			Patch:  patch,
		})
		require.NoError(t, err, patch)
		assert.NotEmpty(t, plan.Patch)
	}
}

func TestPatchPlan_AllowsNonRootSecurityContext(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	plan, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsUser":10001,"runAsNonRoot":true}}]}}}}`,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, plan.Patch)
}

// Dropping capabilities is what a capabilities remediation does, so a patch
// that sets a non-empty drop list is still accepted.
func TestPatchPlan_AllowsDroppingCapabilities(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	plan, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["ALL"]}}}]}}}}`,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, plan.Patch)
}

// A null or empty drop list replaces the live one whole rather than merging
// with it, so a patch that got through would leave the container with the
// runtime's default capabilities. It must never reach the workload.
// A container's runAsGroup overrides the pod's, so a patch that the pod-level check
// refuses must not get through one level down: the pod runs as group 10001, and the
// container would run as group 0.
func TestPatch_ContainerRunAsGroupZeroNeverReachesTheWorkload(t *testing.T) {
	group := int64(10001)
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{RunAsGroup: &group},
			Containers:      []corev1.Container{{Name: "api", Image: "app"}},
		}}},
	}
	client := k8sfake.NewClientset(deploy)
	r := NewPatchRemediator(client)
	target := Target{Kind: "Deployment", Namespace: "payments", Name: "api"}

	_, err := r.Plan(context.Background(), Request{Target: target, Patch: `{"spec":{"template":{"spec":{"securityContext":{"runAsGroup":0}}}}}`})
	require.Error(t, err, "the pod-level patch is refused")

	plan, err := r.Plan(context.Background(), Request{Target: target, Patch: `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsGroup":0}}]}}}}`})
	if err == nil {
		_, err = r.Apply(context.Background(), plan, false)
	}
	got, getErr := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, getErr)
	assert.Nil(t, got.Spec.Template.Spec.Containers[0].SecurityContext, "the container's runAsGroup reached the workload")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "runAsGroup")
}

// A non-root group on a container is still a remediation the patch can make.
func TestPatchPlan_AllowsANonRootContainerGroup(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	plan, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsGroup":10001}}]}}}}`,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, plan.Patch)
}

func TestPatch_DropRemovalNeverReachesTheWorkload(t *testing.T) {
	for _, patch := range []string{
		`{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":null}}}]}}}}`,
		`{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":[]}}}]}}}}`,
	} {
		deploy := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "api", Image: "app", SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				}}},
			}}},
		}
		client := k8sfake.NewClientset(deploy)
		r := NewPatchRemediator(client)
		plan, err := r.Plan(context.Background(), Request{
			Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
			Patch:  patch,
		})
		if err == nil {
			_, err = r.Apply(context.Background(), plan, false)
		}

		got, getErr := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
		require.NoError(t, getErr)
		assert.Equal(t, []corev1.Capability{"ALL"}, got.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities.Drop, "%s", patch)
		require.Error(t, err, "%s", patch)
		assert.Contains(t, err.Error(), "capabilities.drop")
	}
}

func TestPatchApply_RejectsEscalationFieldsEvenWithHandcraftedPlan(t *testing.T) {
	cases := []struct {
		name  string
		patch string
	}{
		{"hostNetwork", `{"spec":{"template":{"spec":{"hostNetwork":true}}}}`},
		{"runAsUser 0", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsUser":0}}]}}}}`},
		{"runAsUser null", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsUser":null}}]}}}}`},
		{"runAsNonRoot false", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsNonRoot":false}}]}}}}`},
		{"runAsNonRoot null", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"runAsNonRoot":null}}]}}}}`},
		{"capabilities.drop null", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":null}}}]}}}}`},
		{"securityContext $patch replace", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"$patch":"replace","readOnlyRootFilesystem":true}}]}}}}`},
		{"securityContext $patch delete", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"$patch":"delete"}}]}}}}`},
		{"securityContext $retainKeys", `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"$retainKeys":["readOnlyRootFilesystem"]}}]}}}}`},
		{"container $patch replace", `{"spec":{"template":{"spec":{"containers":[{"$patch":"replace","name":"api"}]}}}}`},
		{"container $patch delete", `{"spec":{"template":{"spec":{"containers":[{"$patch":"delete","name":"api"}]}}}}`},
		{"container $retainKeys", `{"spec":{"template":{"spec":{"containers":[{"$retainKeys":["name"],"name":"api"}]}}}}`},
		{"pod spec $patch replace", `{"spec":{"template":{"spec":{"$patch":"replace","containers":[{"name":"api"}]}}}}`},
		{"pod spec $patch delete", `{"spec":{"template":{"spec":{"$patch":"delete"}}}}`},
		{"pod spec $retainKeys", `{"spec":{"template":{"spec":{"$retainKeys":["containers"],"containers":[{"name":"api"}]}}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
			r := NewPatchRemediator(client)
			// A Plan built out of band (bypassing Plan()) must still be rejected by
			// Apply — validation belongs at the boundary that performs the write.
			_, err := r.Apply(context.Background(), Plan{
				Action: string(apis.OperatorActionPatch),
				Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Patch:  tc.patch,
			}, false)
			require.Error(t, err)
			assert.Empty(t, client.Actions(), "no client patch call should be made when validation fails")
		})
	}
}

func TestPatchPlan_RejectsDirectives(t *testing.T) {
	cases := []struct {
		name        string
		kind        string
		patch       string
		expectedErr string
	}{
		{
			name:        "securityContext $patch directive",
			kind:        "Deployment",
			patch:       `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"$patch":"replace","readOnlyRootFilesystem":true}}]}}}}`,
			expectedErr: `patch: securityContext directive "$patch" is not allowed in a remediation patch`,
		},
		{
			name:        "securityContext $retainKeys directive",
			kind:        "Deployment",
			patch:       `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"$retainKeys":["readOnlyRootFilesystem"]}}]}}}}`,
			expectedErr: `patch: securityContext directive "$retainKeys" is not allowed in a remediation patch`,
		},
		{
			name:        "container $patch directive",
			kind:        "Deployment",
			patch:       `{"spec":{"template":{"spec":{"containers":[{"$patch":"replace","name":"api"}]}}}}`,
			expectedErr: `patch: container directive "$patch" is not allowed in a remediation patch`,
		},
		{
			name:        "container $retainKeys directive",
			kind:        "Deployment",
			patch:       `{"spec":{"template":{"spec":{"containers":[{"$retainKeys":["name"],"name":"api"}]}}}}`,
			expectedErr: `patch: container directive "$retainKeys" is not allowed in a remediation patch`,
		},
		{
			name:        "pod spec $patch directive",
			kind:        "Deployment",
			patch:       `{"spec":{"template":{"spec":{"$patch":"replace","containers":[{"name":"api"}]}}}}`,
			expectedErr: `patch: pod spec directive "$patch" is not allowed in a remediation patch`,
		},
		{
			name:        "pod spec $retainKeys directive",
			kind:        "Deployment",
			patch:       `{"spec":{"template":{"spec":{"$retainKeys":["containers"],"containers":[{"name":"api"}]}}}}`,
			expectedErr: `patch: pod spec directive "$retainKeys" is not allowed in a remediation patch`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewPatchRemediator(k8sfake.NewClientset())
			_, err := r.Plan(context.Background(), Request{
				Target: Target{Kind: tc.kind, Namespace: "payments", Name: "api"},
				Patch:  tc.patch,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

// ephemeralContainers are subject to the same container-level escalation
// checks as containers/initContainers. The API server only accepts them via a
// subresource, so this denylist coverage is defense-in-depth.
func TestPatchPlan_RejectsEphemeralContainerEscalation(t *testing.T) {
	cases := []struct {
		name  string
		patch string
	}{
		{"ephemeral privileged", `{"spec":{"template":{"spec":{"ephemeralContainers":[{"name":"dbg","securityContext":{"privileged":true}}]}}}}`},
		{"ephemeral allowPrivilegeEscalation", `{"spec":{"template":{"spec":{"ephemeralContainers":[{"name":"dbg","securityContext":{"allowPrivilegeEscalation":true}}]}}}}`},
		{"ephemeral added capabilities", `{"spec":{"template":{"spec":{"ephemeralContainers":[{"name":"dbg","securityContext":{"capabilities":{"add":["SYS_ADMIN"]}}}]}}}}`},
		{"ephemeral image", `{"spec":{"template":{"spec":{"ephemeralContainers":[{"name":"dbg","image":"attacker/img"}]}}}}`},
		{"ephemeral securityContext nulled", `{"spec":{"template":{"spec":{"ephemeralContainers":[{"name":"dbg","securityContext":null}]}}}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewPatchRemediator(k8sfake.NewClientset())
			_, err := r.Plan(context.Background(), Request{
				Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Patch:  c.patch,
			})
			require.Error(t, err, "escalation-relevant ephemeral-container field must be rejected")
			assert.Contains(t, err.Error(), "not allowed")
		})
	}
}

// Pod-level securityContext changes that relax the run-as identity or MAC
// confinement must be rejected, on controller kinds and a bare Pod, for both
// an explicit dangerous value and a null deletion of a hardening field.
func TestPatchPlan_RejectsPodSecurityContextEscalation(t *testing.T) {
	cases := []struct {
		name  string
		kind  string
		patch string
	}{
		{"runAsUser 0 on Deployment", "Deployment", `{"spec":{"template":{"spec":{"securityContext":{"runAsUser":0}}}}}`},
		{"runAsUser 0 on Pod", "Pod", `{"spec":{"securityContext":{"runAsUser":0}}}`},
		{"runAsGroup 0 on Deployment", "Deployment", `{"spec":{"template":{"spec":{"securityContext":{"runAsGroup":0}}}}}`},
		{"runAsNonRoot false on StatefulSet", "StatefulSet", `{"spec":{"template":{"spec":{"securityContext":{"runAsNonRoot":false}}}}}`},
		{"runAsUser nulled", "Deployment", `{"spec":{"template":{"spec":{"securityContext":{"runAsUser":null}}}}}`},
		{"runAsGroup nulled", "Deployment", `{"spec":{"template":{"spec":{"securityContext":{"runAsGroup":null}}}}}`},
		{"runAsNonRoot nulled", "Deployment", `{"spec":{"template":{"spec":{"securityContext":{"runAsNonRoot":null}}}}}`},
		{"whole securityContext nulled", "Deployment", `{"spec":{"template":{"spec":{"securityContext":null}}}}`},
		{"seLinuxOptions on Pod", "Pod", `{"spec":{"securityContext":{"seLinuxOptions":{"type":"spc_t"}}}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewPatchRemediator(k8sfake.NewClientset())
			_, err := r.Plan(context.Background(), Request{
				Target: Target{Kind: c.kind, Namespace: "payments", Name: "api"},
				Patch:  c.patch,
			})
			require.Error(t, err, "escalation-relevant pod securityContext field must be rejected")
			assert.Contains(t, err.Error(), "not allowed")
		})
	}
}

// Safe, hardening pod-level securityContext patches must remain accepted: the
// guard rejects only escalating values, not the whole field.
func TestPatchPlan_AllowsSafePodSecurityContext(t *testing.T) {
	cases := []struct {
		name  string
		patch string
	}{
		{"non-root runAsUser", `{"spec":{"template":{"spec":{"securityContext":{"runAsUser":10001}}}}}`},
		{"non-root runAsUser+runAsGroup", `{"spec":{"template":{"spec":{"securityContext":{"runAsUser":10001,"runAsGroup":10001}}}}}`},
		{"runAsNonRoot true", `{"spec":{"template":{"spec":{"securityContext":{"runAsNonRoot":true}}}}}`},
		{"pod seccompProfile RuntimeDefault", `{"spec":{"template":{"spec":{"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}}}}}}`},
		{"safe sysctl is not blocked", `{"spec":{"template":{"spec":{"securityContext":{"sysctls":[{"name":"net.ipv4.ping_group_range","value":"0 0"}]}}}}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewPatchRemediator(k8sfake.NewClientset())
			plan, err := r.Plan(context.Background(), Request{
				Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Patch:  c.patch,
			})
			require.NoError(t, err, "safe hardening securityContext patch must be accepted")
			assert.NotEmpty(t, plan.Patch)
		})
	}
}

// The pod-level guard must also hold at the Apply boundary, not only in Plan,
// for a handcrafted plan that bypasses Plan().
func TestPatchApply_RejectsPodSecurityContextEscalationEvenWithHandcraftedPlan(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	r := NewPatchRemediator(client)
	_, err := r.Apply(context.Background(), Plan{
		Action: string(apis.OperatorActionPatch),
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"spec":{"template":{"spec":{"securityContext":{"runAsUser":0}}}}}`,
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed")
}

func TestPatchPlan_RejectsNarrowingCapabilitiesDropWhenLiveDropsALL(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "api", Image: "app", SecurityContext: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			}}},
		}}},
	}
	r := NewPatchRemediator(k8sfake.NewClientset(deploy))
	target := Target{Kind: "Deployment", Namespace: "payments", Name: "api"}

	// Patches that drop a subset (narrowing) must be rejected.
	for _, patch := range []string{
		`{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["NET_RAW"]}}}]}}}}`,
		`{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["NET_RAW","SYS_ADMIN"]}}}]}}}}`,
	} {
		_, err := r.Plan(context.Background(), Request{Target: target, Patch: patch})
		require.Error(t, err, "%s", patch)
		assert.Contains(t, err.Error(), "narrows dropped capabilities")
		assert.Contains(t, err.Error(), "live container drops ALL")
	}

	// Patches that still drop ALL must be accepted.
	for _, patch := range []string{
		`{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["ALL"]}}}]}}}}`,
		`{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["all"]}}}]}}}}`,
		`{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["ALL","NET_RAW"]}}}]}}}}`,
	} {
		plan, err := r.Plan(context.Background(), Request{Target: target, Patch: patch})
		require.NoError(t, err, "%s", patch)
		assert.NotEmpty(t, plan.Patch)
	}
}

func TestPatchPlan_RejectsNarrowingCapabilitiesDropWhenLiveDropsSubset(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "api", Image: "app", SecurityContext: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"NET_RAW", "SYS_TIME"}},
			}}},
		}}},
	}
	r := NewPatchRemediator(k8sfake.NewClientset(deploy))
	target := Target{Kind: "Deployment", Namespace: "payments", Name: "api"}

	// Dropping only NET_RAW un-drops SYS_TIME -> must be rejected.
	_, err := r.Plan(context.Background(), Request{
		Target: target,
		Patch:  `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["NET_RAW"]}}}]}}}}`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "narrows dropped capabilities")
	assert.Contains(t, err.Error(), "SYS_TIME")

	// Dropping only SYS_TIME un-drops NET_RAW -> must be rejected.
	_, err = r.Plan(context.Background(), Request{
		Target: target,
		Patch:  `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["SYS_TIME"]}}}]}}}}`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "narrows dropped capabilities")
	assert.Contains(t, err.Error(), "NET_RAW")

	// Patches retaining both (or dropping ALL) must be accepted.
	for _, patch := range []string{
		`{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["ALL"]}}}]}}}}`,
		`{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["NET_RAW","SYS_TIME","CHOWN"]}}}]}}}}`,
		`{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["cap_net_raw","cap_sys_time"]}}}]}}}}`,
	} {
		plan, err := r.Plan(context.Background(), Request{Target: target, Patch: patch})
		require.NoError(t, err, "%s", patch)
		assert.NotEmpty(t, plan.Patch)
	}
}

func TestPatchPlan_AllowsDroppingCapabilitiesWhenLiveDropsNothing(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "api", Image: "app"}},
		}}},
	}
	r := NewPatchRemediator(k8sfake.NewClientset(deploy))
	target := Target{Kind: "Deployment", Namespace: "payments", Name: "api"}

	plan, err := r.Plan(context.Background(), Request{
		Target: target,
		Patch:  `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["NET_RAW"]}}}]}}}}`,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, plan.Patch)
}

func TestPatchPlan_RejectsNarrowingCapabilitiesDropOnInitContainers(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "init", Image: "init-app", SecurityContext: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			}}},
			Containers: []corev1.Container{{Name: "api", Image: "app"}},
		}}},
	}
	r := NewPatchRemediator(k8sfake.NewClientset(deploy))
	target := Target{Kind: "Deployment", Namespace: "payments", Name: "api"}

	// Narrowing init container drop must be rejected.
	_, err := r.Plan(context.Background(), Request{
		Target: target,
		Patch:  `{"spec":{"template":{"spec":{"initContainers":[{"name":"init","securityContext":{"capabilities":{"drop":["NET_RAW"]}}}]}}}}`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "narrows dropped capabilities")
	assert.Contains(t, err.Error(), "init")

	// Keeping ALL on init container must be accepted.
	plan, err := r.Plan(context.Background(), Request{
		Target: target,
		Patch:  `{"spec":{"template":{"spec":{"initContainers":[{"name":"init","securityContext":{"capabilities":{"drop":["ALL"]}}}]}}}}`,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, plan.Patch)
}

func TestPatchPlan_RejectsNarrowingCapabilitiesDropOnEphemeralContainers(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "api", Image: "app"}},
			EphemeralContainers: []corev1.EphemeralContainer{{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name: "debug",
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
					},
				},
			}},
		},
	}
	r := NewPatchRemediator(k8sfake.NewClientset(pod))
	target := Target{Kind: "Pod", Namespace: "payments", Name: "api"}

	_, err := r.Plan(context.Background(), Request{
		Target: target,
		Patch:  `{"spec":{"ephemeralContainers":[{"name":"debug","securityContext":{"capabilities":{"drop":["NET_RAW"]}}}]}}`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "narrows dropped capabilities")
	assert.Contains(t, err.Error(), "debug")
}

func TestPatchApply_RejectsNarrowingCapabilitiesDropEvenWithHandcraftedPlan(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "api", Image: "app", SecurityContext: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			}}},
		}}},
	}
	client := k8sfake.NewClientset(deploy)
	r := NewPatchRemediator(client)

	_, err := r.Apply(context.Background(), Plan{
		Action: string(apis.OperatorActionPatch),
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["NET_RAW"]}}}]}}}}`,
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "narrows dropped capabilities")
}

func TestPatch_DropNarrowingNeverReachesTheWorkload(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "api", Image: "app", SecurityContext: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			}}},
		}}},
	}
	client := k8sfake.NewClientset(deploy)
	r := NewPatchRemediator(client)
	target := Target{Kind: "Deployment", Namespace: "payments", Name: "api"}
	patch := `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["NET_RAW"]}}}]}}}}`

	plan, err := r.Plan(context.Background(), Request{Target: target, Patch: patch})
	if err == nil {
		_, err = r.Apply(context.Background(), plan, false)
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "narrows dropped capabilities")

	got, getErr := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, getErr)
	assert.Equal(t, []corev1.Capability{"ALL"}, got.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities.Drop)
}

func TestPatchPlan_CanonicalizesCapabilityDropNames(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	plan, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["cap_net_raw","  all  "]}}}]}}}}`,
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["NET_RAW","ALL"]}}}]}}}}`, plan.Patch)
}

func TestPatchPlan_PreservesLargeIntegers(t *testing.T) {
	r := NewPatchRemediator(k8sfake.NewClientset())
	// 9007199254740993 is 2^53 + 1, which cannot be represented exactly in float64.
	// Decoding with json.Decoder.UseNumber() preserves the exact integer.
	patch := `{"spec":{"template":{"spec":{"terminationGracePeriodSeconds":9007199254740993}}}}`
	plan, err := r.Plan(context.Background(), Request{
		Target: Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  patch,
	})
	require.NoError(t, err)
	assert.Contains(t, plan.Patch, "9007199254740993")
	assert.NotContains(t, plan.Patch, "9007199254740992")
	assert.JSONEq(t, patch, plan.Patch)
}

func TestPatchApply_CanonicalizesPatchBeforeSending(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"},
	}
	client := k8sfake.NewClientset(deploy)
	r := NewPatchRemediator(client)

	// Handcrafted plan bypassing Plan() with uncanonicalized capability drop names.
	handcraftedPlan := Plan{
		Action:    string(apis.OperatorActionPatch),
		Target:    Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		PatchType: string(types.StrategicMergePatchType),
		Patch:     `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["cap_net_raw","all"]}}}]}}}}`,
	}

	result, err := r.Apply(context.Background(), handcraftedPlan, false)
	require.NoError(t, err)

	// Result.Patch must contain canonicalized capability names.
	assert.JSONEq(t, `{"spec":{"template":{"spec":{"containers":[{"name":"api","securityContext":{"capabilities":{"drop":["NET_RAW","ALL"]}}}]}}}}`, result.Patch)

	// Verify the live object received the canonicalized patch.
	got, err := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, err)
	require.Len(t, got.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, []corev1.Capability{"NET_RAW", "ALL"}, got.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities.Drop)
}

func TestPatchApply_InjectsResourceVersionPrecondition(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api", ResourceVersion: "42"},
	}
	client := k8sfake.NewClientset(deploy)
	r := NewPatchRemediator(client)

	plan := Plan{
		Action:    string(apis.OperatorActionPatch),
		Target:    Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		PatchType: string(types.StrategicMergePatchType),
		Patch:     `{"metadata":{"labels":{"app":"secure"}}}`,
	}

	result, err := r.Apply(context.Background(), plan, false)
	require.NoError(t, err)

	// ResourceVersion from the live object must be injected as a precondition.
	assert.JSONEq(t, `{"metadata":{"labels":{"app":"secure"},"resourceVersion":"42"}}`, result.Patch)
}

func TestPatchApply_RejectsMismatchedResourceVersion(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api", ResourceVersion: "42"},
	}
	client := k8sfake.NewClientset(deploy)
	r := NewPatchRemediator(client)

	plan := Plan{
		Action:    string(apis.OperatorActionPatch),
		Target:    Target{Kind: "Deployment", Namespace: "payments", Name: "api"},
		PatchType: string(types.StrategicMergePatchType),
		Patch:     `{"metadata":{"labels":{"app":"secure"},"resourceVersion":"99"}}`,
	}

	_, err := r.Apply(context.Background(), plan, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resourceVersion \"99\" in patch does not match live object resourceVersion \"42\"")
}
