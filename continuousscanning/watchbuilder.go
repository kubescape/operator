package continuousscanning

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

func NewDynamicWatch(ctx context.Context, client dynamic.Interface, gvr schema.GroupVersionResource, opts metav1.ListOptions) (watch.Interface, error) {
	return client.Resource(gvr).Watch(ctx, opts)
}

type VersionWatch struct {
	gvr schema.GroupVersionResource
	currWatch watch.Interface
}

func (w *VersionWatch) Run(ctx context.Context, out chan<- watch.Event) error {
	for {
		watchEvents := w.currWatch.ResultChan()
		select {
		case event, ok := <-watchEvents:
			if ok {
				out <- event
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func NewWatcher(ctx context.Context, client dynamic.Interface, gvrs []schema.GroupVersionResource, opts metav1.ListOptions) (map[string]watch.Interface, error) {
	watches := map[string]watch.Interface{}

	for idx := range gvrs {
		gvr := gvrs[idx]
		watch, _ := NewDynamicWatch(ctx, client, gvr, opts)

		watches[gvr.String()] = watch
	}

	return watches, nil
}
