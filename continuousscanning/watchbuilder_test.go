package continuousscanning

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
