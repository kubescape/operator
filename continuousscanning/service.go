package continuousscanning

import (
	"context"

	armoapi "github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	watch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	k8sclient "k8s.io/client-go/kubernetes"
)

type EventHandlerFunc func(ctx context.Context, e watch.Event)

type ContinuousScanningService struct {
	shutdownRequested chan struct{}
	workDone          chan struct{}
	k8s               k8sclient.Interface
	k8sdynamic        dynamic.Interface
	eventHandlers     []EventHandlerFunc
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
		logger.L().Ctx(ctx).Info("got event", helpers.Interface("event", e))

		for idx := range s.eventHandlers {
			handler := s.eventHandlers[idx]
			handler(ctx, e)
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

func (s *ContinuousScanningService) AddEventHandler(fn EventHandlerFunc) {
	s.eventHandlers = append(s.eventHandlers, fn)
}

func (s *ContinuousScanningService) Stop() {
	close(s.shutdownRequested)
	<-s.workDone
}

func NewContinuousScanningService(client dynamic.Interface) *ContinuousScanningService {
	doneCh := make(chan struct{})
	eventHandlers := []EventHandlerFunc{}
	eventQueue := make(chan watch.Event, 100)
	workDone := make(chan struct{})

	return &ContinuousScanningService{
		k8sdynamic:        client,
		shutdownRequested: doneCh,
		eventHandlers:     eventHandlers,
		eventQueue:        eventQueue,
		workDone:          workDone,
	}
}
