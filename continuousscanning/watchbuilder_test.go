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

func assertWatchAction(t *testing.T, gotAction ktest.Action, wantGVR schema.GroupVersionResource) {
	t.Helper()
	gotAction, ok := gotAction.(ktest.WatchActionImpl)
	assert.Equalf(t, true, ok, "incorrect action type, expecting watch")

	if ok {
		gotGvr := gotAction.GetResource()

		assert.Equalf(t, wantGVR, gotGvr, "GVR mismatch")
	}


}

func TestWatchBuilder(t *testing.T) {
	tt := []struct {
		name        string
		inputGVR    schema.GroupVersionResource
		wantActions []ktest.Action
		wantErr     error
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
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			opts := metav1.ListOptions{}
			dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())

			_, gotErr := NewDynamicWatch(ctx, dynClient, tc.inputGVR, opts)

			gotActions := dynClient.Actions()

			assertWatchAction(t, gotActions[0], tc.inputGVR)
			assert.ErrorIs(t, gotErr, tc.wantErr)
		})
	}
}
