package continuousscanning

import (
	"context"
	armoapi "github.com/armosec/armoapi-go/apis"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	watch "k8s.io/apimachinery/pkg/watch"
	k8sclient "k8s.io/client-go/kubernetes"
)

type EventHandlerFunc func(e watch.Event)

type ContinuousScanningService struct {
	shutdownRequested chan struct{}
	workDone          chan struct{}
	k8s               k8sclient.Interface
	eventHandlers     []EventHandlerFunc
	eventQueue        chan watch.Event
}

func (s *ContinuousScanningService) listen(ctx context.Context) <-chan armoapi.Command {
	producedCommands := make(chan armoapi.Command)

	listOpts := metav1.ListOptions{}
	podsWatch, _ := s.k8s.CoreV1().Pods("").Watch(ctx, listOpts)
	podEventsCh := podsWatch.ResultChan()

	go func(shutdownCh <-chan struct{}, podEventsCh <-chan watch.Event, out chan<- watch.Event) {
		defer close(out)

		for {
			select {
			case e := <-podEventsCh:
				out <- e
			case <-shutdownCh:
				return
			}
		}

	}(s.shutdownRequested, podEventsCh, s.eventQueue)

	return producedCommands
}

func (s *ContinuousScanningService) work(ctx context.Context) {
	counter := 0
	for e := range s.eventQueue {
		for idx := range s.eventHandlers {
			handler := s.eventHandlers[idx]
			handler(e)
		}
		counter += 1

	}

	close(s.workDone)
}

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

func NewContinuousScanningService(client k8sclient.Interface) *ContinuousScanningService {
	doneCh := make(chan struct{})
	eventHandlers := []EventHandlerFunc{}
	eventQueue := make(chan watch.Event, 100)
	workDone := make(chan struct{})

	return &ContinuousScanningService{
		k8s:               client,
		shutdownRequested: doneCh,
		eventHandlers:     eventHandlers,
		eventQueue:        eventQueue,
		workDone:          workDone,
	}
}
