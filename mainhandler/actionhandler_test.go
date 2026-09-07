package mainhandler

import (
	"context"
	"maps"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/mainhandler/remediators"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
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
	return newActionHandlerForTestWithStorage(t, client, kssfake.NewSimpleClientset(), cfg, args)
}

func newActionHandlerForTestWithStorage(t *testing.T, client kubernetes.Interface, storageClient kssc.Interface, cfg config.IConfig, args apis.OperatorActionArgs) *ActionHandler {
	t.Helper()
	return newActionHandlerForTestWithExtraArgs(t, client, storageClient, cfg, args, nil)
}

// newActionHandlerForTestWithExtraArgs builds an ActionHandler whose
// Command.Args merges args (the typed schema) with extra raw keys — for
// exercising fields not (yet) part of armoapi-go's typed OperatorActionArgs.
// Patch/PatchType no longer need this (they're typed fields as of
// armoapi-go v0.0.761); extra is nil at every current call site.
func newActionHandlerForTestWithExtraArgs(t *testing.T, client kubernetes.Interface, storageClient kssc.Interface, cfg config.IConfig, args apis.OperatorActionArgs, extra map[string]any) *ActionHandler {
	t.Helper()
	argsMap, err := args.ToArgs()
	require.NoError(t, err)
	maps.Copy(argsMap, extra)
	return &ActionHandler{
		k8sAPI:          utils.NewK8sInterfaceFake(client),
		ksStorageClient: storageClient,
		config:          cfg,
		sessionObj: &utils.SessionObj{
			Command: &apis.Command{CommandName: apis.TypeOperatorAction, Args: argsMap},
		},
	}
}

// newActionHandlerForCRDOriginTest builds an ActionHandler whose sessionObj
// carries ParentCommandDetails — i.e. simulates a command delivered via the
// OperatorCommand CRD watcher (watcher/commandshandler.go), the only path
// patch is allowed to arrive on. Without this, sessionObj.ParentCommandDetails
// is nil, simulating a command that arrived via /v1/triggerAction instead.
func newActionHandlerForCRDOriginTest(t *testing.T, client kubernetes.Interface, cfg config.IConfig, args apis.OperatorActionArgs, extra map[string]any) *ActionHandler {
	t.Helper()
	ah := newActionHandlerForTestWithExtraArgs(t, client, kssfake.NewSimpleClientset(), cfg, args, extra)
	ah.sessionObj.SetOperatorCommandDetails(&utils.OperatorCommandDetails{
		Command:   &v1alpha1.OperatorCommand{ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "test-command"}},
		StartedAt: time.Now(),
		Client: &k8sinterface.KubernetesApi{
			KubernetesClient: client,
			DynamicClient:    dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
		},
	})
	return ah
}

func capturePatchDryRun(client *k8sfake.Clientset, resource string, out *[]string) {
	client.PrependReactor("patch", resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
		*out = action.(clienttesting.PatchActionImpl).PatchOptions.DryRun
		return false, nil, nil
	})
}

// capturePatchType records the k8s.io/apimachinery/pkg/types.PatchType of the
// next patch on the given resource, so a test can prove which patch type was
// actually sent to the client rather than only asserting on the resulting
// object state (which is identical for a labels-only body regardless of type).
func capturePatchType(client *k8sfake.Clientset, resource string, out *types.PatchType) {
	client.PrependReactor("patch", resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
		*out = action.(clienttesting.PatchActionImpl).PatchType
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

// A findings-driven selector annotates exactly the workloads that fail the
// requested control — and leaves the ones that pass it untouched.
func TestHandleOperatorAction_SelectorAnnotatesMatchingWorkloads(t *testing.T) {
	client := k8sfake.NewClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "web"}},
	)
	storageClient := kssfake.NewSimpleClientset(
		scanSummary("payments", "Deployment", "api", map[string]spdxv1beta1.ScannedControlSummary{
			"C-0016": failedControl("C-0016", "High"),
		}, spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{High: 1}),
		scanSummary("payments", "Deployment", "web", map[string]spdxv1beta1.ScannedControlSummary{
			"C-0016": passedControl("C-0016", "High"),
		}, spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{}),
	)

	ah := newActionHandlerForTestWithStorage(t, client, storageClient, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action:   apis.OperatorActionAnnotate,
		Selector: &apis.OperatorActionSelector{Control: "C-0016"},
		Reason:   "C-0016",
		DryRun:   boolPtr(false),
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))

	api, err := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "true", api.Annotations[remediators.AnnotationRemediated], "workload failing C-0016 must be annotated")

	web, err := client.AppsV1().Deployments("payments").Get(context.Background(), "web", metav1.GetOptions{})
	require.NoError(t, err)
	_, ok := web.Annotations[remediators.AnnotationRemediated]
	assert.False(t, ok, "workload passing C-0016 must be left untouched")
}

// A selector without --confirm must default to a server-side dry-run for every
// matched workload, never a real write.
func TestHandleOperatorAction_SelectorDefaultsToDryRun(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)
	storageClient := kssfake.NewSimpleClientset(
		scanSummary("payments", "Deployment", "api", map[string]spdxv1beta1.ScannedControlSummary{
			"C-0016": failedControl("C-0016", "High"),
		}, spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{High: 1}),
	)

	ah := newActionHandlerForTestWithStorage(t, client, storageClient, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action:   apis.OperatorActionAnnotate,
		Selector: &apis.OperatorActionSelector{Control: "C-0016"},
		// DryRun intentionally nil
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "a selector action without dryRun must default to server-side dry-run")
}

// A selector that matches no stored finding is an explicit error, not a silent
// no-op, so the caller learns the action had no effect.
func TestHandleOperatorAction_SelectorMatchesNothing(t *testing.T) {
	client := k8sfake.NewClientset()
	storageClient := kssfake.NewSimpleClientset(
		scanSummary("payments", "Deployment", "web", map[string]spdxv1beta1.ScannedControlSummary{
			"C-0016": passedControl("C-0016", "High"),
		}, spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{}),
	)

	ah := newActionHandlerForTestWithStorage(t, client, storageClient, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action:   apis.OperatorActionAnnotate,
		Selector: &apis.OperatorActionSelector{Control: "C-0016"},
	})

	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "matched no workloads")
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

// patch without --confirm must default to a server-side dry-run, never a real
// write — same safe-by-default contract as every other action.
func TestHandleOperatorAction_PatchDefaultsToDryRun(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)

	ah := newActionHandlerForCRDOriginTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionPatch,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"metadata":{"labels":{"seccomp":"applied"}}}`,
		// DryRun intentionally nil
	}, nil)

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "a patch action without dryRun must default to server-side dry-run")
}

// patch --confirm applies the caller-supplied Strategic Merge Patch (the
// default patchType) to the target.
func TestHandleOperatorAction_PatchConfirmWritesStrategicMergePatch(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	var patchType types.PatchType
	capturePatchType(client, "deployments", &patchType)

	ah := newActionHandlerForCRDOriginTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionPatch,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"metadata":{"labels":{"seccomp":"applied"}}}`,
		DryRun: boolPtr(false),
	}, nil)

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	assert.Equal(t, types.StrategicMergePatchType, patchType, "omitting patchType must default to Strategic Merge Patch")

	got, err := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "applied", got.Labels["seccomp"])
}

// patch --confirm with patchType=merge sends a JSON Merge Patch rather than the
// default Strategic Merge Patch.
func TestHandleOperatorAction_PatchConfirmWritesJSONMergePatch(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	var patchType types.PatchType
	capturePatchType(client, "deployments", &patchType)

	ah := newActionHandlerForCRDOriginTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action:    apis.OperatorActionPatch,
		Target:    &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:     `{"metadata":{"labels":{"seccomp":"applied"}}}`,
		PatchType: "merge",
		DryRun:    boolPtr(false),
	}, nil)

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	assert.Equal(t, types.MergePatchType, patchType, "patchType=merge must send a JSON Merge Patch, not the default Strategic Merge Patch")

	got, err := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "applied", got.Labels["seccomp"])
}

// A patch action in an excluded namespace must be rejected before any write,
// same as every other action.
func TestHandleOperatorAction_PatchExcludedNamespace(t *testing.T) {
	client := k8sfake.NewClientset()
	cfg := newTestConfig(config.Config{Namespace: "kubescape", ExcludeNamespaces: []string{"kube-system"}})

	ah := newActionHandlerForCRDOriginTest(t, client, cfg, apis.OperatorActionArgs{
		Action: apis.OperatorActionPatch,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "kube-system", Name: "api"},
		Patch:  `{"metadata":{"labels":{"seccomp":"applied"}}}`,
		DryRun: boolPtr(false),
	}, nil)

	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "excluded from remediation")
}

// A patch action with no 'patch' payload in Command.Args is rejected before
// any cluster write is attempted.
func TestHandleOperatorAction_PatchMissingPayload(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})

	ah := newActionHandlerForCRDOriginTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionPatch,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		DryRun: boolPtr(false),
	}, nil)

	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a 'patch' payload")
}

// An invalid JSON/YAML 'patch' payload is rejected at Plan time, before any
// cluster write is attempted.
func TestHandleOperatorAction_PatchInvalidPayload(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})

	ah := newActionHandlerForCRDOriginTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionPatch,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{not valid: [`,
		DryRun: boolPtr(false),
	}, nil)

	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid patch payload")
}

// An unsupported patchType is rejected before any cluster write is attempted.
func TestHandleOperatorAction_PatchUnsupportedPatchType(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})

	ah := newActionHandlerForCRDOriginTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action:    apis.OperatorActionPatch,
		Target:    &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:     `{"metadata":{"labels":{"seccomp":"applied"}}}`,
		PatchType: "json-patch",
		DryRun:    boolPtr(false),
	}, nil)

	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported patchType")
}

// The core regression test for this gate: a patch action that arrives without
// ParentCommandDetails set — i.e. delivered via /v1/triggerAction rather than
// the RBAC-gated OperatorCommand CRD watcher — must be rejected before any
// payload parsing or cluster write, unlike annotate/quarantine/revert which
// are legitimately deliverable via triggerAction (the CLI's `operator
// remediate` subcommand's only transport).
func TestHandleOperatorAction_PatchRejectedWithoutCRDOrigin(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)

	ah := newActionHandlerForTestWithExtraArgs(t, client, kssfake.NewSimpleClientset(), newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionPatch,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Patch:  `{"metadata":{"labels":{"seccomp":"applied"}}}`,
		DryRun: boolPtr(false),
	}, nil)

	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OperatorCommand CRD delivery path")
	assert.Empty(t, dryRun, "a rejected patch must never reach the client, dry-run or not")

	got, getErr := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, getErr)
	assert.NotContains(t, got.Labels, "seccomp", "a rejected patch must not touch the target at all")
}

// annotate/quarantine/revert must remain reachable without CRD origin: they
// are the CLI's `operator remediate` subcommand's only transport
// (/v1/triggerAction over kubectl port-forward), and this gate is specific to
// patch, not a blanket requirement on every operatorAction.
func TestHandleOperatorAction_AnnotateAllowedWithoutCRDOrigin(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})

	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Reason: "C-0016",
		DryRun: boolPtr(false),
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	got, err := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "true", got.Annotations[remediators.AnnotationRemediated])
}
