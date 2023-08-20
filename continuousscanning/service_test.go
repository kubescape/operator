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

	armoapi "github.com/armosec/armoapi-go/apis"
	armowlid "github.com/armosec/utils-k8s-go/wlid"
	opautilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
	"github.com/stretchr/testify/assert"
)

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
			Kind:       "Pod",
			APIVersion: "v1",
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
	t.Helper()

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

type spyHandler struct {
	mx     *sync.RWMutex
	called bool
	wg     *sync.WaitGroup
}

func (h *spyHandler) Handle(ctx context.Context, e watch.Event) error {
	if !h.Called() {
		h.mx.Lock()
		h.called = true
		h.mx.Unlock()

		h.wg.Done()
	}

	return nil
}

func (h *spyHandler) Called() bool {
	h.mx.RLock()
	res := h.called
	h.mx.RUnlock()
	return res
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
			resourcesCreatedWg := &sync.WaitGroup{}
			dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
			// We use the spy handler later to verify if it's been called
			spyH := &spyHandler{called: false, wg: resourcesCreatedWg, mx: &sync.RWMutex{}}
			css := NewContinuousScanningService(dynClient, spyH)
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

			assert.Equal(t, true, spyH.Called())
		})
	}
}

func makePodScanObject(p *corev1.Pod) *objectsenvelopes.ScanObject {
	gvk := p.GroupVersionKind()
	so := &objectsenvelopes.ScanObject{
		ApiVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Metadata: objectsenvelopes.ScanObjectMetadata{
			Name:      p.GetName(),
			Namespace: p.GetNamespace(),
		},
	}
	return so
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
					CommandName: armoapi.TypeRunKubescape,
					Wlid: makeWlid(clusterNameStub, namespaceStub, "Pod", "first"),
					Args: map[string]interface{}{
						utils.KubescapeScanV1: opautilsmetav1.PostScanRequest{
							ScanObject: makePodScanObject(makePod("default", "first")),
						},
					},
				},
				{
					CommandName: armoapi.TypeRunKubescape,
					Wlid: makeWlid(clusterNameStub, namespaceStub, "Pod", "second"),
					Args: map[string]interface{}{
						utils.KubescapeScanV1: opautilsmetav1.PostScanRequest{
							ScanObject: makePodScanObject(makePod("default", "second")),
						},
					},
				},
				{
					CommandName: armoapi.TypeRunKubescape,
					Wlid: makeWlid(clusterNameStub, namespaceStub, "Pod", "third"),
					Args: map[string]interface{}{
						utils.KubescapeScanV1: opautilsmetav1.PostScanRequest{
							ScanObject: makePodScanObject(makePod("default", "third")),
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			// client := fake.NewSimpleClientset()
			dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
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
			ph := NewTriggeringHandler(wp, clusterNameStub)
			css := NewContinuousScanningService(dynClient, ph)
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

			assert.Equal(t, tc.want, gotCommands.Commands())
		})
	}
}
