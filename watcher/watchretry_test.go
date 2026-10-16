package watcher

import (
	"context"
	"net/http"
	"sync"
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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
		{name: "expired drops it", event: watch.Event{Type: watch.Error, Object: &apierrors.NewResourceExpired("too old resource version").ErrStatus}, want: ""},
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

func TestDropGoneVersionOnlyForAGoneVersion(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "expired", err: apierrors.NewResourceExpired("too old resource version"), want: ""},
		{name: "gone", err: apierrors.NewGone("gone"), want: ""},
		{name: "other status", err: apierrors.NewServiceUnavailable("busy"), want: "3"},
		{name: "plain error", err: assert.AnError, want: "3"},
		{name: "no error", err: nil, want: "3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := metav1.ListOptions{ResourceVersion: "3"}
			dropGoneVersion(&opts, tt.err)
			assert.Equal(t, tt.want, opts.ResourceVersion)
		})
	}
}

// scriptedWatches answers each Watch call with a fresh fake watcher, or with the error
// the test armed for the next call, and records the resourceVersion the call asked to
// resume from.
type scriptedWatches struct {
	versions chan string
	watchers chan *watch.FakeWatcher
	mu       sync.Mutex
	failNext error
}

func newScriptedWatches() *scriptedWatches {
	return &scriptedWatches{versions: make(chan string, 8), watchers: make(chan *watch.FakeWatcher, 8)}
}

func (sw *scriptedWatches) failNextCall(err error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.failNext = err
}

func (sw *scriptedWatches) react(action k8stesting.Action) (bool, watch.Interface, error) {
	sw.versions <- action.(k8stesting.WatchAction).GetWatchRestrictions().ResourceVersion
	sw.mu.Lock()
	err := sw.failNext
	sw.failNext = nil
	sw.mu.Unlock()
	if err != nil {
		return true, nil, err
	}
	fw := watch.NewFake()
	sw.watchers <- fw
	return true, fw, nil
}

// failedCall waits for the version of a Watch call that was answered with an error.
func (sw *scriptedWatches) failedCall(t *testing.T) string {
	t.Helper()
	select {
	case version := <-sw.versions:
		return version
	case <-time.After(10 * time.Second):
		t.Fatal("no new watch was attempted")
	}
	return ""
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

	fourth, version := watches.next(t)
	assert.Equal(t, "9", version, "a closed channel resumes from the last object")
	watches.failNextCall(apierrors.NewResourceExpired("too old resource version"))
	fourth.Stop()

	assert.Equal(t, "9", watches.failedCall(t))
	_, version = watches.next(t)
	assert.Equal(t, "", version, "a watch request refused as expired starts over from the current state")
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

	second, version := watches.next(t)
	assert.Equal(t, "12", version, "an in-flight command must not be dispatched again after a server error")
	watches.failNextCall(apierrors.NewGone("gone"))
	second.Stop()

	assert.Equal(t, "12", watches.failedCall(t))
	_, version = watches.next(t)
	assert.Equal(t, "", version)
}
