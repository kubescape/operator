package rulesupdate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newFakeDynamicClient() *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			v1alpha1.SchemaGroupVersionResource: "OperatorCommandList",
		},
	)
}

func TestNewRulesUpdator_NonPositiveIntervalUsesDefault(t *testing.T) {
	for _, interval := range []time.Duration{0, -5 * time.Second} {
		updater := NewRulesUpdator(context.Background(), nil, RulesUpdaterConfig{
			Interval:  interval,
			Namespace: "kubescape",
		})
		assert.Equal(t, defaultUpdateInterval, updater.interval)
		updater.Stop()
	}
}

func TestSendUpdateRulesCommand_CreatesOperatorCommand(t *testing.T) {
	dynClient := newFakeDynamicClient()
	k8sClient := &k8sinterface.KubernetesApi{DynamicClient: dynClient}
	updater := NewRulesUpdator(context.Background(), k8sClient, RulesUpdaterConfig{
		Interval:  time.Minute,
		Namespace: "kubescape",
	})
	defer updater.Stop()

	err := updater.SendUpdateRulesCommand()
	require.NoError(t, err)

	list, err := dynClient.Resource(v1alpha1.SchemaGroupVersionResource).Namespace("kubescape").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, list.Items, 1)

	item := list.Items[0]
	assert.True(t, strings.HasPrefix(item.GetName(), "update-rules-"))
	assert.Equal(t, "kubescape", item.GetNamespace())
	assert.Equal(t, "node-agent", item.GetLabels()["kubescape.io/app-name"])
	assert.Equal(t, "operator", item.GetLabels()["kubescape.io/node-name"])

	var gotCmd v1alpha1.OperatorCommand
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &gotCmd)
	require.NoError(t, err)
	assert.Equal(t, OperatorCommandTypeRuntimeUpdateRules, gotCmd.Spec.CommandType)
	assert.Equal(t, "v1", gotCmd.Spec.CommandVersion)
	assert.NotEmpty(t, gotCmd.Spec.GUID)
}

func TestSendUpdateRulesCommand_NilClientReturnsError(t *testing.T) {
	updater := NewRulesUpdator(context.Background(), nil, RulesUpdaterConfig{
		Interval:  time.Minute,
		Namespace: "kubescape",
	})
	defer updater.Stop()

	assert.Error(t, updater.SendUpdateRulesCommand())

	updaterWithNilDynamic := NewRulesUpdator(context.Background(), &k8sinterface.KubernetesApi{}, RulesUpdaterConfig{
		Interval:  time.Minute,
		Namespace: "kubescape",
	})
	defer updaterWithNilDynamic.Stop()

	assert.Error(t, updaterWithNilDynamic.SendUpdateRulesCommand())
}

func TestSendUpdateRulesCommand_PropagatesCreateError(t *testing.T) {
	dynClient := newFakeDynamicClient()
	dynClient.PrependReactor("create", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("api server unavailable")
	})

	k8sClient := &k8sinterface.KubernetesApi{DynamicClient: dynClient}
	updater := NewRulesUpdator(context.Background(), k8sClient, RulesUpdaterConfig{
		Interval:  time.Minute,
		Namespace: "kubescape",
	})
	defer updater.Stop()

	err := updater.SendUpdateRulesCommand()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api server unavailable")
}

func TestStartAndStop(t *testing.T) {
	dynClient := newFakeDynamicClient()
	k8sClient := &k8sinterface.KubernetesApi{DynamicClient: dynClient}
	updater := NewRulesUpdator(context.Background(), k8sClient, RulesUpdaterConfig{
		Interval:  15 * time.Millisecond,
		Namespace: "kubescape",
	})

	updater.Start()

	require.Eventually(t, func() bool {
		list, err := dynClient.Resource(v1alpha1.SchemaGroupVersionResource).Namespace("kubescape").List(context.Background(), metav1.ListOptions{})
		return err == nil && len(list.Items) >= 2
	}, time.Second, 10*time.Millisecond)

	updater.Stop()

	// Allow any in-flight tick to finish before recording the stable count.
	time.Sleep(40 * time.Millisecond)
	listAfterStop, err := dynClient.Resource(v1alpha1.SchemaGroupVersionResource).Namespace("kubescape").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	countAfterStop := len(listAfterStop.Items)

	time.Sleep(50 * time.Millisecond)
	listLater, err := dynClient.Resource(v1alpha1.SchemaGroupVersionResource).Namespace("kubescape").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, countAfterStop, len(listLater.Items), "updater should stop creating commands after Stop()")
}
