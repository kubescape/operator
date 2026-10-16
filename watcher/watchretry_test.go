package watcher

import (
	"context"
	"net/http"
	"testing"
	"time"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func watchStatus(code int32) *metav1.Status {
	return &metav1.Status{Status: metav1.StatusFailure, Code: code, Message: "watch failed"}
}

func TestResumeFromTakesTheVersionFromObjectsOnly(t *testing.T) {
	pod := func(rv string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "a", ResourceVersion: rv}}
	}
	tests := []struct {
		name  string
		event watch.Event
		want  string
	}{
		{name: "added", event: watch.Event{Type: watch.Added, Object: pod("5")}, want: "5"},
		{name: "modified", event: watch.Event{Type: watch.Modified, Object: pod("6")}, want: "6"},
		{name: "deleted", event: watch.Event{Type: watch.Deleted, Object: pod("7")}, want: "7"},
		{name: "bookmark", event: watch.Event{Type: watch.Bookmark, Object: pod("8")}, want: "8"},
		{name: "error keeps the version", event: watch.Event{Type: watch.Error, Object: watchStatus(http.StatusInternalServerError)}, want: "3"},
		{name: "gone drops it", event: watch.Event{Type: watch.Error, Object: watchStatus(http.StatusGone)}, want: ""},
		{name: "closed channel keeps the version", event: watch.Event{}, want: "3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := metav1.ListOptions{ResourceVersion: "3"}
			resumeFrom(&opts, tt.event)
			assert.Equal(t, tt.want, opts.ResourceVersion)
		})
	}
}

// scriptedWatches answers each Watch call with a fresh fake watcher and records the
// resourceVersion the call asked to resume from.
type scriptedWatches struct {
	versions chan string
	watchers chan *watch.FakeWatcher
}

func newScriptedWatches() *scriptedWatches {
	return &scriptedWatches{versions: make(chan string, 8), watchers: make(chan *watch.FakeWatcher, 8)}
}

func (sw *scriptedWatches) react(action k8stesting.Action) (bool, watch.Interface, error) {
	sw.versions <- action.(k8stesting.WatchAction).GetWatchRestrictions().ResourceVersion
	fw := watch.NewFake()
	sw.watchers <- fw
	return true, fw, nil
}

func (sw *scriptedWatches) next(t *testing.T) (*watch.FakeWatcher, string) {
	t.Helper()
	select {
	case fw := <-sw.watchers:
		return fw, <-sw.versions
	case <-time.After(10 * time.Second):
		t.Fatal("no new watch was opened")
	}
	return nil, ""
}

func TestWatchRetryResumesWhereItLeftOff(t *testing.T) {
	cfg, err := config.LoadConfig("../configuration")
	require.NoError(t, err)
	operatorConfig, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{ClusterName: "test"}, &beUtils.Credentials{}, cfg)
	require.NoError(t, err)
	k8sClient := k8sfake.NewSimpleClientset()
	watches := newScriptedWatches()
	k8sClient.PrependWatchReactor("pods", watches.react)
	wh := NewWatchHandler(operatorConfig, utils.NewK8sInterfaceFake(k8sClient), kssfake.NewSimpleClientset(), NewCooldownQueue())
	// The loop never returns on its own; giving up logs fatally, so the queue stays open.
	go wh.watchRetry(context.Background(), metav1.ListOptions{Watch: true})

	first, version := watches.next(t)
	assert.Equal(t, "", version)
	first.Add(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "default", ResourceVersion: "5"}})
	first.Error(watchStatus(http.StatusInternalServerError))

	second, version := watches.next(t)
	assert.Equal(t, "5", version, "a server error is not a reason to replay every pod")
	second.Error(watchStatus(http.StatusGone))

	third, version := watches.next(t)
	assert.Equal(t, "", version, "a gone version can only be followed by the current state")
	third.Add(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "default", ResourceVersion: "9"}})
	third.Stop()

	_, version = watches.next(t)
	assert.Equal(t, "9", version, "a closed channel resumes from the last object")
}

func TestCommandWatchRetryResumesWhereItLeftOff(t *testing.T) {
	operatorConfig, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{}, &beUtils.Credentials{}, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)
	dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	watches := newScriptedWatches()
	dynClient.PrependWatchReactor("operatorcommands", watches.react)
	k8sAPI := utils.NewK8sInterfaceFake(k8sfake.NewSimpleClientset())
	k8sAPI.DynamicClient = dynClient
	cwh := NewCommandWatchHandler(k8sAPI, operatorConfig)
	go cwh.watchRetry(context.Background())

	command := func(rv string) *unstructured.Unstructured {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(v1alpha1.SchemaGroupVersionResource.GroupVersion().WithKind("OperatorCommand"))
		u.SetNamespace("kubescape")
		u.SetName("scan")
		u.SetResourceVersion(rv)
		return u
	}
	first, version := watches.next(t)
	assert.Equal(t, "", version)
	first.Add(command("12"))
	first.Error(watchStatus(http.StatusServiceUnavailable))

	_, version = watches.next(t)
	assert.Equal(t, "12", version, "an in-flight command must not be dispatched again after a server error")
}
