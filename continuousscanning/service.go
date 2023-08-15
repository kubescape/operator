package continuousscanning

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	watch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	k8sclient "k8s.io/client-go/kubernetes"

	armoapi "github.com/armosec/armoapi-go/apis"
	armowlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
)

type EventHandler interface {
	Handle(ctx context.Context, e watch.Event) error
}

type ContinuousScanningService struct {
	shutdownRequested chan struct{}
	workDone          chan struct{}
	k8s               k8sclient.Interface
	k8sdynamic        dynamic.Interface
	eventHandlers     []EventHandler
	eventQueue        chan watch.Event
}

func (s *ContinuousScanningService) listen(ctx context.Context) <-chan armoapi.Command {
	producedCommands := make(chan armoapi.Command)

	listOpts := metav1.ListOptions{}
	resourceEventsCh := make(chan watch.Event, 100)

	gvrs := []schema.GroupVersionResource{
		{
			Group:    "",
			Version:  "v1",
			Resource: "Pods",
		},
	}
	wp, _ := NewWatchPool(ctx, s.k8sdynamic, gvrs, listOpts)
	wp.Run(ctx, resourceEventsCh)

	go func(shutdownCh <-chan struct{}, resourceEventsCh <-chan watch.Event, out chan<- watch.Event) {
		defer close(out)

		for {
			select {
			case e := <-resourceEventsCh:
				out <- e
			case <-shutdownCh:
				return
			}
		}

	}(s.shutdownRequested, resourceEventsCh, s.eventQueue)

	return producedCommands
}

func (s *ContinuousScanningService) work(ctx context.Context) {
	for e := range s.eventQueue {
		for idx := range s.eventHandlers {
			handler := s.eventHandlers[idx]
			handler.Handle(ctx, e)
		}
	}

	close(s.workDone)
}

// Launch launches the service.
//
// It sets up the provided watches, listens for events they deliver in the
// background and dispatches them to registered event handlers.
// Launch blocks until all the underlying watches are ready to accept events.
func (s *ContinuousScanningService) Launch(ctx context.Context) <-chan armoapi.Command {
	out := make(chan armoapi.Command)

	s.listen(ctx)
	go s.work(ctx)

	return out
}

func (s *ContinuousScanningService) AddEventHandler(fn EventHandler) {
	s.eventHandlers = append(s.eventHandlers, fn)
}

func (s *ContinuousScanningService) Stop() {
	close(s.shutdownRequested)
	<-s.workDone
}

func NewContinuousScanningService(client dynamic.Interface, h ...EventHandler) *ContinuousScanningService {
	doneCh := make(chan struct{})
	eventQueue := make(chan watch.Event, 100)
	workDone := make(chan struct{})

	return &ContinuousScanningService{
		k8sdynamic:        client,
		shutdownRequested: doneCh,
		eventHandlers:     h,
		eventQueue:        eventQueue,
		workDone:          workDone,
	}
}

type poolInvokerHandler struct {
	wp          *ants.PoolWithFunc
	clusterName string
}

func triggerScan(ctx context.Context, wp *ants.PoolWithFunc, clusterName string, e watch.Event) error {
	obj := e.Object.(*unstructured.Unstructured)
	objRaw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return err
	}

	unstructuredObj := &unstructured.Unstructured{Object: objRaw}
	objKind := unstructuredObj.GetKind()
	objName := unstructuredObj.GetName()
	objNamespace := unstructuredObj.GetNamespace()
	wlid := armowlid.GetK8sWLID(clusterName, objNamespace, objKind, objName)

	command := armoapi.Command{Wlid: wlid}
	utils.AddCommandToChannel(ctx, &command, wp)

	return nil
}

func (h *poolInvokerHandler) Handle(ctx context.Context, e watch.Event) error {
	return triggerScan(ctx, h.wp, h.clusterName, e)
}

func NewTriggeringHandler(wp *ants.PoolWithFunc, clusterName string) EventHandler {
	return &poolInvokerHandler{wp: wp, clusterName: clusterName}
}
