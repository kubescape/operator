package continuousscanning

import (
	"context"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

// NewDynamicWatch starts a watch for the given GVR.
//
// namespace restricts a namespace-scoped resource to that namespace. An
// empty namespace watches all of them. A cluster-scoped resource ignores
// it, since there is nothing to scope.
func NewDynamicWatch(ctx context.Context, client dynamic.Interface, gvr schema.GroupVersionResource, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	var w watch.Interface
	var err error
	if k8sinterface.IsNamespaceScope(&gvr) {
		w, err = client.Resource(gvr).Namespace(namespace).Watch(ctx, opts)
	} else {
		w, err = client.Resource(gvr).Watch(ctx, opts)
	}
	return w, err
}

type SelfHealingWatch struct {
	opts          metav1.ListOptions
	client        dynamic.Interface
	currWatch     watch.Interface
	makeWatchFunc func(ctx context.Context, client dynamic.Interface, gvr schema.GroupVersionResource, namespace string, opts metav1.ListOptions) (watch.Interface, error)
	gvr           schema.GroupVersionResource
	namespace     string
}

func NewSelfHealingWatch(client dynamic.Interface, gvr schema.GroupVersionResource, namespace string, opts metav1.ListOptions) *SelfHealingWatch {
	return &SelfHealingWatch{
		client:        client,
		gvr:           gvr,
		namespace:     namespace,
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
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (w *SelfHealingWatch) Run(ctx context.Context, readyWg *sync.WaitGroup, out chan<- watch.Event) error {
	watchInitializedAtLeastOnce := false

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			gvr := helpers.String("gvr", w.gvr.String())
			logger.L().Debug("creating watch for GVR", gvr)
			watchFunc, err := w.makeWatchFunc(ctx, w.client, w.gvr, w.namespace, w.opts)
			if err != nil {
				logger.L().Ctx(ctx).Warning(
					"got error when creating a watch for gvr",
					gvr,
					helpers.Error(err),
				)
				continue
			}
			logger.L().Debug("watch created\n")
			w.currWatch = watchFunc

			// Watch is considered ready once it is successfully acquired
			// Signal we are done only the first time because
			// WaitGroups panic when trying to decrease below zero
			if !watchInitializedAtLeastOnce {
				readyWg.Done()
				watchInitializedAtLeastOnce = true
			}
			w.RunUntilWatchCloses(ctx, out)
		}

	}
}

type WatchPool struct {
	pool []*SelfHealingWatch
}

func (wp *WatchPool) Run(ctx context.Context, out chan<- watch.Event) {
	logger.L().Info("Watch pool: starting")

	wg := &sync.WaitGroup{}
	for idx := range wp.pool {
		wg.Add(1)
		go wp.pool[idx].Run(ctx, wg, out)
	}
	wg.Wait()

	logger.L().Info("Watch pool: started ok")
}

// NewWatchPool builds one watch per GVR per namespace.
//
// An empty namespaces slice keeps the previous behaviour of a single watch
// per GVR across the whole cluster.
func NewWatchPool(_ context.Context, client dynamic.Interface, gvrs []schema.GroupVersionResource, namespaces []string, opts metav1.ListOptions) (*WatchPool, error) {
	if len(namespaces) == 0 {
		namespaces = []string{""}
	}

	watches := make([]*SelfHealingWatch, 0, len(gvrs)*len(namespaces))

	for idx := range gvrs {
		gvr := gvrs[idx]
		for _, namespace := range namespaces {
			watches = append(watches, NewSelfHealingWatch(client, gvr, namespace, opts))
		}
	}

	pool := &WatchPool{pool: watches}

	return pool, nil
}
