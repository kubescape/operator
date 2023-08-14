package continuousscanning

import (
	"context"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktest "k8s.io/client-go/testing"

	armoapi "github.com/armosec/armoapi-go/apis"
	armowlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
	"github.com/stretchr/testify/assert"
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

func makePod(namespace, name string) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

func makeWlid(clusterName, namespace, kind, name string) string {
	return armowlid.GetK8sWLID(clusterName, namespace, kind, name)
}

func createUnstructuredPod(t *testing.T, ctx context.Context, dClient dynamic.Interface, gvr schema.GroupVersionResource, namespace string, pod *corev1.Pod, createOpts metav1.CreateOptions) error {
	dynPods := dClient.Resource(gvr).Namespace(namespace)
	podRaw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pod)
	if err != nil {
		t.Fatalf("unable to convert object to unstructured: %v", err)
		return err
	}

	podUnstructured := &unstructured.Unstructured{Object: podRaw}
	_, err = dynPods.Create(ctx, podUnstructured, createOpts)
	if err != nil {
		t.Fatalf("Unable to create pod dynamically: %v", err)
		return err
	}
	return nil
}

func TestAddEventHandler(t *testing.T) {
	namespaceStub := "default"
	tt := []struct {
		name  string
		input []*corev1.Pod
	}{
		{
			name: "an added event handler should be called on new events",
			input: []*corev1.Pod{
				makePod("default", "first"),
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
			css := NewContinuousScanningService(dynClient)

			resourcesCreatedWg := &sync.WaitGroup{}

			// We use the spy handler later to verify if it's been called
			called := &struct {
				mx     *sync.Mutex
				called bool
				wg     *sync.WaitGroup
			}{called: false, wg: resourcesCreatedWg, mx: &sync.Mutex{}}
			spyHandler := func(ctx context.Context, e watch.Event) {
				if !called.called {
					called.mx.Lock()
					called.called = true
					called.mx.Unlock()

					called.wg.Done()
				}
			}
			css.AddEventHandler(spyHandler)
			css.Launch(ctx)

			// Create Pods to be listened
			podsGvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "Pods"}
			createOpts := metav1.CreateOptions{}
			for _, podToCreate := range tc.input {
				// Since the fake K8s client does not wait for
				// creates to write to the event channel, try
				// to sync with a WaitGroup
				resourcesCreatedWg.Add(1)
				pod := podToCreate
				createUnstructuredPod(t, ctx, dynClient, podsGvr, namespaceStub, pod, createOpts)
			}

			// wait for all Creates to complete
			resourcesCreatedWg.Wait()
			css.Stop()

			assert.Equal(t, true, called.called)
		})
	}
}

func TestContinuousScanningService(t *testing.T) {
	clusterNameStub := "clusterCHANGEME"
	namespaceStub := "default"
	tt := []struct {
		name  string
		input []*corev1.Pod
		want  []armoapi.Command
	}{
		{
			name: "recognized event should produce a scan command",
			input: []*corev1.Pod{
				makePod("default", "first"),
				makePod("default", "second"),
				makePod("default", "third"),
			},
			want: []armoapi.Command{
				{
					Wlid: makeWlid(clusterNameStub, namespaceStub, "Pod", "first"),
				},
				{
					Wlid: makeWlid(clusterNameStub, namespaceStub, "Pod", "second"),
				},
				{
					Wlid: makeWlid(clusterNameStub, namespaceStub, "Pod", "third"),
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			// client := fake.NewSimpleClientset()
			dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
			css := NewContinuousScanningService(dynClient)
			resourcesCreatedWg := &sync.WaitGroup{}
			podsGvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "Pods"}
			gotCommands := newSyncSlice[armoapi.Command]()

			// Attach processing function as closure so it captures
			// the commands being created
			processingFunc := func(i interface{}) {
				j := i.(utils.Job)

				command := j.Obj().Command
				gotCommands.Add(command)

				resourcesCreatedWg.Done()
			}
			wp, _ := ants.NewPoolWithFunc(1, processingFunc)

			handleEvent := func(ctx context.Context, e watch.Event) {
				// TriggerScan(ctx, e, wp)

				obj := e.Object.(*unstructured.Unstructured)
				objRaw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
				if err != nil {
					t.Fatalf("handling err: %v", err)
				}

				unstructuredObj := &unstructured.Unstructured{Object: objRaw}
				clusterName := clusterNameStub
				objKind := unstructuredObj.GetKind()
				objName := unstructuredObj.GetName()
				objNamespace := unstructuredObj.GetNamespace()
				wlid := armowlid.GetK8sWLID(clusterName, objNamespace, objKind, objName)

				command := armoapi.Command{Wlid: wlid}
				utils.AddCommandToChannel(ctx, &command, wp)
			}
			css.AddEventHandler(handleEvent)

			// Once events handlers have been added, launch
			css.Launch(ctx)

			// Create Pods to be listened
			createOpts := metav1.CreateOptions{}
			for _, podToCreate := range tc.input {
				createUnstructuredPod(t, ctx, dynClient, podsGvr, namespaceStub, podToCreate, createOpts)

				// Since the fake K8s client does not wait for
				// creates to write to the event channel, try
				// to sync with WaitGroups
				resourcesCreatedWg.Add(1)
			}

			// wait for all Creates to complete
			resourcesCreatedWg.Wait()
			css.Stop()

			assert.ElementsMatch(t, tc.want, gotCommands.Commands())
		})
	}
}
