package continuousscanning

import (
	"context"

	armoapi "github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/watcher"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

type ContinuousScanningService struct {
	cfg               config.IConfig
	tl                TargetLoader
	shutdownRequested chan struct{}
	workDone          chan struct{}
	k8sdynamic        dynamic.Interface
	eventHandlers     []EventHandler
	eventQueue        *watcher.CooldownQueue
}

func (s *ContinuousScanningService) listen(ctx context.Context) <-chan armoapi.Command {
	producedCommands := make(chan armoapi.Command)

	listOpts := metav1.ListOptions{}
	resourceEventsCh := make(chan watch.Event, 100)

	gvrs := s.tl.LoadGVRs(ctx)
	logger.L().Info("fetched gvrs", helpers.Interface("gvrs", gvrs))
	wp, _ := NewWatchPool(ctx, s.k8sdynamic, gvrs, listOpts)
	wp.Run(ctx, resourceEventsCh)
	logger.L().Info("ran watch pool")

	go func(shutdownCh <-chan struct{}, resourceEventsCh <-chan watch.Event, out *watcher.CooldownQueue) {
		defer out.Stop()

		for {
			select {
			case e := <-resourceEventsCh:
				logger.L().Debug(
					"got event from channel",
					helpers.Interface("event", e),
				)
				if s.cfg.SkipNamespace(e.Object.(metav1.Object).GetNamespace()) {
					continue
				}
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
		logger.L().Debug(
			"got an event to process",
			helpers.Interface("event", e),
		)
		for idx := range s.eventHandlers {
			handler := s.eventHandlers[idx]
			err := handler.Handle(ctx, e)
			if err != nil {
				logger.L().Ctx(ctx).Error(
					"failed to handle event",
					helpers.Interface("event", e),
					helpers.Error(err),
				)
			}
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

func NewContinuousScanningService(cfg config.IConfig, client dynamic.Interface, tl TargetLoader, h ...EventHandler) *ContinuousScanningService {
	doneCh := make(chan struct{})
	eventQueue := watcher.NewCooldownQueue()
	workDone := make(chan struct{})

	return &ContinuousScanningService{
		cfg:               cfg,
		tl:                tl,
		k8sdynamic:        client,
		shutdownRequested: doneCh,
		eventHandlers:     h,
		eventQueue:        eventQueue,
		workDone:          workDone,
	}
}
