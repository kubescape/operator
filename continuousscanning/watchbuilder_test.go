package continuousscanning

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktest "k8s.io/client-go/testing"
)

func assertWatchAction(t *testing.T, gotAction ktest.Action, wantGVR schema.GroupVersionResource, wantNamespace string) {
	t.Helper()
	gotAction, ok := gotAction.(ktest.WatchActionImpl)
	assert.Equalf(t, true, ok, "incorrect action type, expecting watch")

	if ok {
		gotGvr := gotAction.GetResource()

		assert.Equalf(t, wantGVR, gotGvr, "GVR mismatch")
		assert.Equalf(t, wantNamespace, gotAction.GetNamespace(), "namespace mismatch")
	}

}

func TestNewDynamicWatch(t *testing.T) {
	tt := []struct {
		wantErr        error
		inputGVR       schema.GroupVersionResource
		name           string
		inputNamespace string
		wantNamespace  string
		wantActions    []ktest.Action
	}{
		{
			name: "",
			inputGVR: schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "Pods",
			},
			wantActions: []ktest.Action{},
			wantErr:     nil,
		},
		{
			name: "a namespace is passed through to the watch",
			inputGVR: schema.GroupVersionResource{
				Group:    "apps",
				Version:  "v1",
				Resource: "deployments",
			},
			inputNamespace: "kube-system",
			wantNamespace:  "kube-system",
			wantActions:    []ktest.Action{},
			wantErr:        nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			opts := metav1.ListOptions{}
			dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())

			_, gotErr := NewDynamicWatch(ctx, dynClient, tc.inputGVR, tc.inputNamespace, opts)

			gotActions := dynClient.Actions()

			assertWatchAction(t, gotActions[0], tc.inputGVR, tc.wantNamespace)
			assert.ErrorIs(t, gotErr, tc.wantErr)
		})
	}
}

func TestNewWatchPoolNamespaces(t *testing.T) {
	gvrs := []schema.GroupVersionResource{
		{Group: "apps", Version: "v1", Resource: "deployments"},
		{Group: "", Version: "v1", Resource: "pods"},
	}

	tt := []struct {
		name            string
		inputNamespaces []string
		wantWatches     int
	}{
		{
			name:            "no namespaces keeps one watch per gvr",
			inputNamespaces: nil,
			wantWatches:     2,
		},
		{
			name:            "each namespace gets its own watch per gvr",
			inputNamespaces: []string{"default", "kube-system"},
			wantWatches:     4,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())

			pool, err := NewWatchPool(ctx, dynClient, gvrs, tc.inputNamespaces, metav1.ListOptions{})

			assert.NoError(t, err)
			assert.Len(t, pool.pool, tc.wantWatches)

			gotNamespaces := map[string]int{}
			for _, w := range pool.pool {
				gotNamespaces[w.namespace]++
			}
			if len(tc.inputNamespaces) == 0 {
				assert.Equal(t, map[string]int{"": len(gvrs)}, gotNamespaces)
				return
			}
			for _, namespace := range tc.inputNamespaces {
				assert.Equalf(t, len(gvrs), gotNamespaces[namespace], "namespace %q", namespace)
			}
		})
	}
}

func TestNewWatchPoolClusterScopedGVRs(t *testing.T) {
	clusterRoles := schema.GroupVersionResource{
		Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles",
	}
	nodes := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}
	deployments := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

	tt := []struct {
		name            string
		inputGVRs       []schema.GroupVersionResource
		inputNamespaces []string
		wantWatches     int
		wantNamespaces  map[string]int
	}{
		{
			name:            "a cluster scoped gvr gets one watch whatever the namespaces say",
			inputGVRs:       []schema.GroupVersionResource{clusterRoles, nodes},
			inputNamespaces: []string{"default", "kube-system", "kubescape"},
			wantWatches:     2,
			wantNamespaces:  map[string]int{"": 2},
		},
		{
			name:            "a mixed rule set fans out only the namespaced gvr",
			inputGVRs:       []schema.GroupVersionResource{clusterRoles, deployments},
			inputNamespaces: []string{"default", "kube-system"},
			// one for clusterroles, two for deployments
			wantWatches:    3,
			wantNamespaces: map[string]int{"": 1, "default": 1, "kube-system": 1},
		},
		{
			name:            "a cluster scoped gvr with no namespaces is unchanged",
			inputGVRs:       []schema.GroupVersionResource{clusterRoles},
			inputNamespaces: nil,
			wantWatches:     1,
			wantNamespaces:  map[string]int{"": 1},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())

			pool, err := NewWatchPool(ctx, dynClient, tc.inputGVRs, tc.inputNamespaces, metav1.ListOptions{})

			assert.NoError(t, err)
			assert.Len(t, pool.pool, tc.wantWatches)

			gotNamespaces := map[string]int{}
			for _, w := range pool.pool {
				gotNamespaces[w.namespace]++
			}
			assert.Equal(t, tc.wantNamespaces, gotNamespaces)
		})
	}
}

// TestSelfHealingWatchReconnect checks what an ended watch leaves for the next one. The
// next watch has to carry on from the last object: started without a version, the server
// replays every object as ADDED and each one is scanned again.
func TestSelfHealingWatchReconnect(t *testing.T) {
	object := func(version string) *unstructured.Unstructured {
		o := &unstructured.Unstructured{}
		o.SetKind("Deployment")
		o.SetNamespace("default")
		o.SetName("app")
		o.SetResourceVersion(version)
		return o
	}
	failure := func(code int32, reason metav1.StatusReason) *metav1.Status {
		return &metav1.Status{Status: metav1.StatusFailure, Code: code, Reason: reason}
	}

	tt := []struct {
		name          string
		events        []watch.Event
		wantResume    string
		wantForwarded int
	}{
		{
			name: "resumes from the last object",
			events: []watch.Event{
				{Type: watch.Added, Object: object("7")},
				{Type: watch.Modified, Object: object("8")},
			},
			wantResume:    "8",
			wantForwarded: 2,
		},
		{
			name: "an error event is not forwarded and keeps the version",
			events: []watch.Event{
				{Type: watch.Added, Object: object("7")},
				{Type: watch.Error, Object: failure(http.StatusInternalServerError, metav1.StatusReasonInternalError)},
			},
			wantResume:    "7",
			wantForwarded: 1,
		},
		{
			name: "an expired version is forgotten",
			events: []watch.Event{
				{Type: watch.Added, Object: object("7")},
				{Type: watch.Error, Object: failure(http.StatusGone, metav1.StatusReasonExpired)},
			},
			wantResume:    "",
			wantForwarded: 1,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			first := watch.NewFakeWithChanSize(len(tc.events), false)
			for _, e := range tc.events {
				first.Action(e.Type, e.Object)
			}
			first.Stop()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var calls []metav1.ListOptions
			w := NewSelfHealingWatch(nil, schema.GroupVersionResource{}, "", metav1.ListOptions{})
			w.makeWatchFunc = func(_ context.Context, _ dynamic.Interface, _ schema.GroupVersionResource, _ string, opts metav1.ListOptions) (watch.Interface, error) {
				calls = append(calls, opts)
				if len(calls) == 1 {
					return first, nil
				}
				cancel() // the reconnect is what this test is after
				return nil, errors.New("stop")
			}

			ready := &sync.WaitGroup{}
			ready.Add(1)
			out := make(chan watch.Event, len(tc.events))
			assert.ErrorIs(t, w.Run(ctx, ready, out), context.Canceled)

			assert.Len(t, calls, 2)
			assert.Equal(t, tc.wantResume, calls[1].ResourceVersion)
			assert.Len(t, out, tc.wantForwarded)
		})
	}
}
