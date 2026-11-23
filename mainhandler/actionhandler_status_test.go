package mainhandler

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/mainhandler/remediators"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// recordOperatorCommandStatuses makes ah run as a command from an
// OperatorCommand, and records every status it writes to that command.
func recordOperatorCommandStatuses(t *testing.T, ah *ActionHandler) *[]v1alpha1.OperatorCommandStatus {
	t.Helper()
	statuses := &[]v1alpha1.OperatorCommandStatus{}
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	dynamicClient.PrependReactor("patch", "*", func(action clienttesting.Action) (bool, runtime.Object, error) {
		var body struct {
			Status v1alpha1.OperatorCommandStatus `json:"status"`
		}
		require.NoError(t, json.Unmarshal(action.(clienttesting.PatchAction).GetPatch(), &body))
		*statuses = append(*statuses, body.Status)
		return true, &unstructured.Unstructured{}, nil
	})
	ah.sessionObj.SetOperatorCommandDetails(&utils.OperatorCommandDetails{
		Command:   &v1alpha1.OperatorCommand{ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "test-command"}},
		StartedAt: time.Now(),
		Client: &k8sinterface.KubernetesApi{
			KubernetesClient: ah.k8sAPI.KubernetesClient,
			DynamicClient:    dynamicClient,
		},
	})
	return statuses
}

func failingC0016Summaries(names ...string) *kssfake.Clientset {
	var objects []runtime.Object
	for _, name := range names {
		objects = append(objects, scanSummary("payments", "Deployment", name, map[string]spdxv1beta1.ScannedControlSummary{
			"C-0016": failedControl("C-0016", "High"),
		}, spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{High: 1}))
	}
	return kssfake.NewClientset(objects...)
}

func selectorAnnotateArgs() apis.OperatorActionArgs {
	return apis.OperatorActionArgs{
		Action:   apis.OperatorActionAnnotate,
		Selector: &apis.OperatorActionSelector{Control: "C-0016"},
		Reason:   "C-0016",
		DryRun:   boolPtr(false),
	}
}

// A selector run whose second target fails must never report the command as
// completed without an error: a client watching the command (the CLI polls it)
// takes that as success.
func TestHandleOperatorAction_SelectorNeverReportsSuccessBeforeAFailingTarget(t *testing.T) {
	// "web" failed C-0016 in the stored scan but no longer exists.
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	ah := newActionHandlerForTestWithStorage(t, client, failingC0016Summaries("api", "web"),
		newTestConfig(config.Config{Namespace: "kubescape"}), selectorAnnotateArgs())
	statuses := recordOperatorCommandStatuses(t, ah)

	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)

	require.NotEmpty(t, *statuses)
	for i, status := range *statuses {
		assert.False(t, status.Completed && status.Error == nil, "status %d reports success before the run finished: %+v", i, status)
	}
	last := (*statuses)[len(*statuses)-1]
	require.NotNil(t, last.Error)
	assert.Contains(t, last.Error.Message, "Deployment/payments/web")
	var results []remediators.Result
	require.NoError(t, json.Unmarshal(last.Payload, &results))
	require.Len(t, results, 1, "the target that went through is still recorded")
	assert.Equal(t, "api", results[0].Target.Name)
}

// A selector run that succeeds writes one status, with every target's result.
func TestHandleOperatorAction_SelectorWritesOneStatusWithEveryResult(t *testing.T) {
	client := k8sfake.NewClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "web"}},
	)
	ah := newActionHandlerForTestWithStorage(t, client, failingC0016Summaries("api", "web"),
		newTestConfig(config.Config{Namespace: "kubescape"}), selectorAnnotateArgs())
	statuses := recordOperatorCommandStatuses(t, ah)

	require.NoError(t, ah.handleOperatorAction(context.Background()))

	require.Len(t, *statuses, 1)
	status := (*statuses)[0]
	assert.True(t, status.Completed)
	assert.Nil(t, status.Error)
	var results []remediators.Result
	require.NoError(t, json.Unmarshal(status.Payload, &results))
	names := []string{}
	for _, r := range results {
		names = append(names, r.Target.Name)
	}
	assert.ElementsMatch(t, []string{"api", "web"}, names)
}

// A single target still writes its own result, as before.
func TestHandleOperatorAction_SingleTargetStillWritesItsResult(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	ah := newActionHandlerForTestWithStorage(t, client, failingC0016Summaries("api"),
		newTestConfig(config.Config{Namespace: "kubescape"}), selectorAnnotateArgs())
	statuses := recordOperatorCommandStatuses(t, ah)

	require.NoError(t, ah.handleOperatorAction(context.Background()))

	require.Len(t, *statuses, 1)
	var result remediators.Result
	require.NoError(t, json.Unmarshal((*statuses)[0].Payload, &result))
	assert.Equal(t, "api", result.Target.Name)
}
