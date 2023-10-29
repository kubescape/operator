package continuousscanning

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	watch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"

	armoapi "github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type ContinuousScanningService struct {
	tl                TargetLoader
	shutdownRequested chan struct{}
	workDone          chan struct{}
	k8sdynamic        dynamic.Interface
	eventHandlers     []EventHandler
	eventQueue        *cooldownQueue
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

	go func(shutdownCh <-chan struct{}, resourceEventsCh <-chan watch.Event, out *cooldownQueue) {
		defer out.Stop()

		for {
			select {
			case e := <-resourceEventsCh:
				logger.L().Ctx(ctx).Info(
					"got event from channel",
					helpers.Interface("event", e),
				)
				out.Enqueue(e)
			case <-shutdownCh:
				return
			}
		}

	}(s.shutdownRequested, resourceEventsCh, s.eventQueue)

	return producedCommands
}

func (s *ContinuousScanningService) work(ctx context.Context) {
	for e := range s.eventQueue.ResultChan {
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

func NewContinuousScanningService(client dynamic.Interface, tl TargetLoader, queueSize int, sameEventCooldown time.Duration, h ...EventHandler) *ContinuousScanningService {
	doneCh := make(chan struct{})
	eventQueue := NewCooldownQueue(queueSize, sameEventCooldown)
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
