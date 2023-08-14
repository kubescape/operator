package continuousscanning

import (
	// "time"
	"context"
	"sync"
	"testing"

	armoapi "github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"

	// corev1 "k8s.io/api/core/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	// k8sclient "k8s.io/client-go/kubernetes"
	"github.com/panjf2000/ants/v2"
	fake "k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"

	"github.com/kubescape/operator/utils"
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

func TestNewDynamicWatch(t *testing.T) {
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

type syncSlice[T any] struct {
	data []T
	mx   sync.Mutex
}

func newSyncSlice[T any]() *syncSlice[T] {
	return &syncSlice[T]{
		data: []T{},
		mx:   sync.Mutex{},
	}
}

func (s *syncSlice[T]) Add(v T) {
	s.mx.Lock()
	s.data = append(s.data, v)
	s.mx.Unlock()
}

func (s *syncSlice[T]) Commands() []T {
	s.mx.Lock()
	result := s.data
	s.mx.Unlock()
	return result
}

func TestContinuousScanningService(t *testing.T) {
	tt := []struct {
		name  string
		input []*corev1.Pod
		want  []armoapi.Command
	}{
		{
			name: "recognized event should produce a scan command",
			input: []*corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "first",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "second",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "third",
					},
				},
			},
			want: []armoapi.Command{
				{
					Wlid: "first",
				},
				{
					Wlid: "second",
				},
				{
					Wlid: "third",
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			client := fake.NewSimpleClientset()
			// dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
			wg := &sync.WaitGroup{}

			css := NewContinuousScanningService(client)
			css.Launch(ctx)

			gotCommands := newSyncSlice[armoapi.Command]()

			// Attach processing function as closure so it captures
			// the commands being created
			processingFunc := func(i interface{}) {
				j := i.(utils.Job)

				command := j.Obj().Command
				gotCommands.Add(command)

				wg.Done()
			}

			wp, _ := ants.NewPoolWithFunc(3, processingFunc)
			handleEvent := func(e watch.Event) {
				obj := e.Object.(*corev1.Pod)
				objName := obj.ObjectMeta.Name
				command := armoapi.Command{Wlid: objName}
				utils.AddCommandToChannel(ctx, &command, wp)
			}
			css.AddEventHandler(handleEvent)

			// Create Pods to be listened
			createOpts := metav1.CreateOptions{}
			for _, podToCreate := range tc.input {
				pod := podToCreate
				client.CoreV1().Pods("default").Create(ctx, pod, createOpts)
				// Since the fake K8s client does not wait for
				// creates to write to the event channel, try
				// to sync with WaitGroups
				wg.Add(1)
			}

			// wait for all Creates to complete
			wg.Wait()
			css.Stop()

			assert.ElementsMatch(t, tc.want, gotCommands.Commands())
		})
	}
}
