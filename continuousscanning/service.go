package continuousscanning

import (
	"context"
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	k8sclient "k8s.io/client-go/kubernetes"

	armoapi "github.com/armosec/armoapi-go/apis"
	armowlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	opautilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
)

type EventHandler interface {
	Handle(ctx context.Context, e watch.Event) error
}

type ContinuousScanningService struct {
	tl                TargetLoader
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

	gvrs := s.tl.LoadGVRs(ctx)
	logger.L().Ctx(ctx).Info("fetched gvrs", helpers.Interface("gvrs", gvrs))
	wp, _ := NewWatchPool(ctx, s.k8sdynamic, gvrs, listOpts)
	wp.Run(ctx, resourceEventsCh)
	logger.L().Ctx(ctx).Info("ran watch pool")

	go func(shutdownCh <-chan struct{}, resourceEventsCh <-chan watch.Event, out chan<- watch.Event) {
		defer close(out)

		for {
			select {
			case e := <-resourceEventsCh:
				logger.L().Ctx(ctx).Info(
					"got event from channel",
					helpers.Interface("event", e),
				)
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

func NewContinuousScanningService(client dynamic.Interface, tl TargetLoader, h ...EventHandler) *ContinuousScanningService {
	doneCh := make(chan struct{})
	eventQueue := make(chan watch.Event, 100)
	workDone := make(chan struct{})

	return &ContinuousScanningService{
		tl:                tl,
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

func makeScanArgs(so *objectsenvelopes.ScanObject) map[string]interface{} {
	psr := opautilsmetav1.PostScanRequest{
		ScanObject: so,
	}
	return map[string]interface{}{
		utils.KubescapeScanV1: psr,
	}

}

func makeScanCommand(clusterName string, uo *unstructured.Unstructured) *armoapi.Command {
	objKind := uo.GetKind()
	objName := uo.GetName()
	objNamespace := uo.GetNamespace()
	wlid := armowlid.GetK8sWLID(clusterName, objNamespace, objKind, objName)

	scanObject, _ := unstructuredToScanObject(uo)

	args := makeScanArgs(scanObject)

	return &armoapi.Command{
		CommandName: armoapi.TypeRunKubescape,
		Wlid:        wlid,
		Args:        args,
	}
}

func triggerScan(ctx context.Context, wp *ants.PoolWithFunc, clusterName string, e watch.Event) error {
	logger.L().Ctx(ctx).Info(
		"triggering scan",
		helpers.String("clusterName", clusterName),
		helpers.Interface("event", e),
	)
	obj := e.Object.(*unstructured.Unstructured)
	objRaw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return err
	}

	uObject := &unstructured.Unstructured{Object: objRaw}
	command := makeScanCommand(clusterName, uObject)
	utils.AddCommandToChannel(ctx, command, wp)

	return nil
}

func unstructuredToScanObject(uo *unstructured.Unstructured) (*objectsenvelopes.ScanObject, error) {
	var res *objectsenvelopes.ScanObject
	if res = objectsenvelopes.NewScanObject(uo.UnstructuredContent()); res == nil {
		return res, errors.New("passed object cannot be converted to ScanObject")
	}
	return res, nil
}

func (h *poolInvokerHandler) Handle(ctx context.Context, e watch.Event) error {
	return triggerScan(ctx, h.wp, h.clusterName, e)
}

func NewTriggeringHandler(wp *ants.PoolWithFunc, clusterName string) EventHandler {
	return &poolInvokerHandler{wp: wp, clusterName: clusterName}
}
