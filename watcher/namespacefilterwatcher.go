package watcher

import (
	"context"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const NamespaceFiltersKey = "namespaceFilters.json"

// NamespaceFilterWatcher owns the live namespace filter source. Run and
// WaitForReady must use the process context, including during startup.
type NamespaceFilterWatcher struct {
	informer cache.SharedIndexInformer
	cfg      *config.OperatorConfig
	name     string
	ready    chan struct{}
	once     sync.Once
}

func NewNamespaceFilterWatcher(client kubernetes.Interface, cfg *config.OperatorConfig, name string) (*NamespaceFilterWatcher, error) {
	w := &NamespaceFilterWatcher{cfg: cfg, name: name, ready: make(chan struct{})}
	w.informer = coreinformers.NewFilteredConfigMapInformer(client, cfg.Namespace(), 0, cache.Indexers{}, func(opts *metav1.ListOptions) {
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
	})
	_, err := w.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.apply,
		UpdateFunc: func(_, obj interface{}) { w.apply(obj) },
		DeleteFunc: func(_ interface{}) {
			logger.L().Warning("namespace filter ConfigMap deleted; retaining last valid filters", helpers.String("configMap", name))
		},
	})
	if err != nil {
		return nil, err
	}
	return w, nil
}

func (w *NamespaceFilterWatcher) apply(obj interface{}) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || cm.Namespace != w.cfg.Namespace() || cm.Name != w.name {
		return
	}
	data, ok := cm.Data[NamespaceFiltersKey]
	if !ok {
		logger.L().Warning("namespace filter ConfigMap is missing namespaceFilters.json; retaining last valid filters", helpers.String("configMap", w.name))
		return
	}
	changed, err := w.cfg.UpdateNamespaceFilters([]byte(data))
	if err != nil {
		logger.L().Warning("namespace filter ConfigMap rejected; retaining last valid filters", helpers.String("configMap", w.name), helpers.Error(err))
		return
	}
	if changed {
		logger.L().Info("namespace filters updated", helpers.String("configMap", w.name), helpers.String("resourceVersion", cm.ResourceVersion))
	}
	w.once.Do(func() { close(w.ready) })
}

// Run blocks until cancellation. The informer relists and reconnects on API
// failures; failures never replace the last successfully validated snapshot.
func (w *NamespaceFilterWatcher) Run(ctx context.Context) {
	logger.L().Info("waiting for valid namespace filter ConfigMap", helpers.String("configMap", w.name), helpers.String("namespace", w.cfg.Namespace()))
	w.informer.Run(ctx.Done())
}

func (w *NamespaceFilterWatcher) WaitForReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.ready:
		return ctx.Err()
	}
}
