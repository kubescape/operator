package continuousscanning

import (
	"fmt"
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

func NewDynamicWatch(ctx context.Context, client dynamic.Interface, gvr schema.GroupVersionResource, opts metav1.ListOptions) (watch.Interface, error) {
	return client.Resource(gvr).Watch(ctx, opts)
}

type SelfHealingWatch struct {
	client        dynamic.Interface
	gvr           schema.GroupVersionResource
	opts          metav1.ListOptions
	makeWatchFunc func(ctx context.Context, client dynamic.Interface, gvr schema.GroupVersionResource, opts metav1.ListOptions) (watch.Interface, error)
	currWatch     watch.Interface
}

func NewSelfHealingWatch(client dynamic.Interface, gvr schema.GroupVersionResource, opts metav1.ListOptions) *SelfHealingWatch {
	return &SelfHealingWatch{
		client:        client,
		gvr:           gvr,
		opts:          opts,
		makeWatchFunc: NewDynamicWatch,
	}
}

func (w *SelfHealingWatch) RunUntilWatchCloses(ctx context.Context, out chan<- watch.Event) error {
	for {
		watchEvents := w.currWatch.ResultChan()
		select {
		case event, ok := <-watchEvents:
			if ok {
				out <- event
			} else {
				continue
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (w *SelfHealingWatch) Run(ctx context.Context, out chan<- watch.Event) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fmt.Printf("creating watch for GVR: %s\n", w.gvr.String())
			watch, err := w.makeWatchFunc(ctx, w.client, w.gvr, w.opts)
			if err != nil {
				fmt.Printf("got error with watch: %v", err)
				continue
			}
			fmt.Printf("watch created: %v\n", watch)
			w.currWatch = watch
			w.RunUntilWatchCloses(ctx, out)
		}

	}
}

type WatchPool struct {
	pool []*SelfHealingWatch
}

func (wp *WatchPool) Run(ctx context.Context, out chan<- watch.Event) {
	fmt.Printf("Starting pool\n")
	for idx := range wp.pool {
		go wp.pool[idx].Run(ctx, out)
	}
}

func NewWatchPool(ctx context.Context, client dynamic.Interface, gvrs []schema.GroupVersionResource, opts metav1.ListOptions) (*WatchPool, error) {
	watches := make([]*SelfHealingWatch, len(gvrs))

	for idx := range gvrs {
		gvr := gvrs[idx]
		watch := NewSelfHealingWatch(client, gvr, opts)

		watches[idx] = watch
	}

	pool := &WatchPool{pool: watches}

	return pool, nil
}
