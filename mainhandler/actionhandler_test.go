package mainhandler

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/mainhandler/remediators"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func boolPtr(b bool) *bool { return &b }

func deploymentWithSelectorForHandler(ns, name string, selector map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: selector}},
	}
}

func networkPolicyForHandler(ns, name string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
}

func newTestConfig(serviceConfig config.Config) config.IConfig {
	return config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{}, &beUtils.Credentials{}, serviceConfig)
}

func newActionHandlerForTest(t *testing.T, client kubernetes.Interface, cfg config.IConfig, args apis.OperatorActionArgs) *ActionHandler {
	t.Helper()
	argsMap, err := args.ToArgs()
	require.NoError(t, err)
	return &ActionHandler{
		k8sAPI: utils.NewK8sInterfaceFake(client),
		config: cfg,
		sessionObj: &utils.SessionObj{
			Command: &apis.Command{CommandName: apis.TypeOperatorAction, Args: argsMap},
		},
	}
}

func capturePatchDryRun(client *k8sfake.Clientset, resource string, out *[]string) {
	client.PrependReactor("patch", resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
		*out = action.(clienttesting.PatchActionImpl).PatchOptions.DryRun
		return false, nil, nil
	})
}

// Omitting dryRun must default to a safe server-side dry-run, never a real write.
func TestHandleOperatorAction_AnnotateDefaultsToDryRun(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)

	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Reason: "C-0016",
		// DryRun intentionally nil
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "a command without dryRun must default to server-side dry-run")
}

// Explicit dryRun=false (the CLI's --confirm) performs a real write.
func TestHandleOperatorAction_AnnotateConfirmWrites(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)

	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Reason: "C-0016",
		DryRun: boolPtr(false),
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	assert.Empty(t, dryRun, "a confirmed action must not request dry-run")

	got, err := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "true", got.Annotations[remediators.AnnotationRemediated])
	assert.Equal(t, "C-0016", got.Annotations[remediators.AnnotationReason])
}

func TestHandleOperatorAction_RevertRemovesAnnotations(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "payments",
		Name:        "api",
		Annotations: map[string]string{remediators.AnnotationRemediated: "true", remediators.AnnotationReason: "C-0016"},
	}})

	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionRevert,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		DryRun: boolPtr(false), // --confirm: revert is a real write
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))

	got, err := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, err)
	_, ok := got.Annotations[remediators.AnnotationRemediated]
	assert.False(t, ok)
}

// Revert must honor the safe-by-default contract: with dryRun unset it previews
// (server-side dry-run) and must not actually remove the annotations.
func TestHandleOperatorAction_RevertDefaultsToDryRun(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "payments",
		Name:        "api",
		Annotations: map[string]string{remediators.AnnotationRemediated: "true", remediators.AnnotationReason: "C-0016"},
	}})
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)

	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionRevert,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		// DryRun intentionally nil
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "a revert without dryRun must default to server-side dry-run")
}

// A namespaced target with no namespace must be rejected up front rather than
// slipping past the excluded-namespace rail and failing late at the API server.
func TestHandleOperatorAction_NamespacedKindRequiresNamespace(t *testing.T) {
	client := k8sfake.NewClientset()
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Name: "api"},
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a namespace")
}

func TestHandleOperatorAction_ExcludedNamespaceRejected(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	cfg := newTestConfig(config.Config{Namespace: "kubescape", ExcludeNamespaces: []string{"payments"}})

	ah := newActionHandlerForTest(t, client, cfg, apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
	})

	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "excluded from remediation")
}

func TestHandleOperatorAction_SelectorTargetingNotYetSupported(t *testing.T) {
	client := k8sfake.NewClientset()
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action:   apis.OperatorActionAnnotate,
		Selector: &apis.OperatorActionSelector{Control: "C-0016", MinSeverity: "High"},
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "selector targeting is not supported yet")
}

func TestHandleOperatorAction_TargetRequired(t *testing.T) {
	client := k8sfake.NewClientset()
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a target is required")
}

func TestHandleOperatorAction_UnimplementedActions(t *testing.T) {
	client := k8sfake.NewClientset()
	cfg := newTestConfig(config.Config{Namespace: "kubescape"})
	for _, action := range []apis.OperatorActionType{apis.OperatorActionCordon} {
		ah := newActionHandlerForTest(t, client, cfg, apis.OperatorActionArgs{
			Action: action,
			Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		})
		err := ah.handleOperatorAction(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not implemented yet")
	}
}

// quarantine without --confirm must create the deny-all NetworkPolicy as a
// server-side dry-run, never a real write.
func TestHandleOperatorAction_QuarantineDefaultsToDryRun(t *testing.T) {
	client := k8sfake.NewClientset(deploymentWithSelectorForHandler("payments", "api", map[string]string{"app": "api"}))
	var dryRun []string
	client.PrependReactor("create", "networkpolicies", func(action clienttesting.Action) (bool, runtime.Object, error) {
		dryRun = action.(clienttesting.CreateActionImpl).CreateOptions.DryRun
		return false, nil, nil
	})

	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionQuarantine,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Reason: "C-0016",
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "quarantine without dryRun must default to server-side dry-run")
}

// quarantine --confirm writes the NetworkPolicy isolating the workload's pods.
func TestHandleOperatorAction_QuarantineConfirmWrites(t *testing.T) {
	client := k8sfake.NewClientset(deploymentWithSelectorForHandler("payments", "api", map[string]string{"app": "api"}))
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionQuarantine,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		DryRun: boolPtr(false),
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	got, err := client.NetworkingV1().NetworkPolicies("payments").Get(context.Background(), "kubescape-quarantine-deployment-api", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "api"}, got.Spec.PodSelector.MatchLabels)
}

// A quarantine target in an excluded namespace must be rejected before any write.
func TestHandleOperatorAction_QuarantineExcludedNamespace(t *testing.T) {
	client := k8sfake.NewClientset()
	cfg := newTestConfig(config.Config{Namespace: "kubescape", ExcludeNamespaces: []string{"kube-system"}})
	ah := newActionHandlerForTest(t, client, cfg, apis.OperatorActionArgs{
		Action: apis.OperatorActionQuarantine,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "kube-system", Name: "api"},
		DryRun: boolPtr(false),
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "excluded from remediation")

	// The rejection must happen before any cluster write — no NetworkPolicy may
	// have been created in the excluded namespace.
	nps, listErr := client.NetworkingV1().NetworkPolicies("kube-system").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, listErr)
	assert.Empty(t, nps.Items, "excluded namespace must be rejected before any NetworkPolicy write")
}

// revert undoes quarantine (deletes the NetworkPolicy) even when the workload was
// never annotated — without the caller naming which action to undo.
func TestHandleOperatorAction_RevertDeletesQuarantine(t *testing.T) {
	np := networkPolicyForHandler("payments", "kubescape-quarantine-deployment-api")
	client := k8sfake.NewClientset(np)
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionRevert,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		DryRun: boolPtr(false),
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	_, err := client.NetworkingV1().NetworkPolicies("payments").Get(context.Background(), "kubescape-quarantine-deployment-api", metav1.GetOptions{})
	assert.Error(t, err, "revert must delete the quarantine NetworkPolicy")
}

func TestHandleOperatorAction_UnknownAction(t *testing.T) {
	client := k8sfake.NewClientset()
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionType("teleport"),
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown action")
}

// A malformed ttl must be rejected up front, not trusted (see armoapi-go#655).
func TestHandleOperatorAction_InvalidTTLRejected(t *testing.T) {
	client := k8sfake.NewClientset()
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		TTL:    "banana",
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ttl")
}

// A well-formed ttl must still be fenced (auto-revert is a later phase) rather
// than silently accepted, so a caller is not misled into expecting auto-revert.
func TestHandleOperatorAction_ValidTTLNotYetSupported(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		TTL:    "24h",
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ttl/auto-revert is not supported yet")
}
