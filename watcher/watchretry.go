package watcher

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type resourceVersionGetter interface {
	GetResourceVersion() string
}

var errWatchClosed = errors.New("watch channel closed")

func (wh *WatchHandler) watchRetry(ctx context.Context, watchOpts v1.ListOptions) {
	if err := backoff.RetryNotify(func() error {
		watcher, err := wh.k8sAPI.KubernetesClient.CoreV1().Pods("").Watch(context.Background(), watchOpts)
		if err != nil {
			return fmt.Errorf("client resource: %w", err)
		}
		for {
			event, chanActive := <-watcher.ResultChan()
			// set resource version to resume watch from
			// inspired by https://github.com/kubernetes/client-go/blob/5a0a4247921dd9e72d158aaa6c1ee124aba1da80/tools/watch/retrywatcher.go#L157
			if metaObject, ok := event.Object.(resourceVersionGetter); ok {
				watchOpts.ResourceVersion = metaObject.GetResourceVersion()
			}
			if wh.eventQueue.Closed() {
				watcher.Stop()
				return backoff.Permanent(errors.New("event queue closed"))
			}
			if !chanActive {
				// channel closed, retry
				return errWatchClosed
			}
			if event.Type == watch.Error {
				return fmt.Errorf("watch error: %s", event.Object)
			}
			pod := event.Object.(*corev1.Pod)
			if wh.cfg.SkipNamespace(pod.Namespace) {
				continue
			}
			wh.eventQueue.Enqueue(event)
		}
	}, newBackOff(), func(err error, d time.Duration) {
		if !errors.Is(err, errWatchClosed) {
			logger.L().Ctx(ctx).Warning("watch", helpers.Error(err),
				helpers.String("resource", "pods"),
				helpers.String("retry in", d.String()))
		}
	}); err != nil {
		logger.L().Ctx(ctx).Fatal("giving up watch", helpers.Error(err),
			helpers.String("resource", "pods"))
	}
}

func newBackOff() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	// never stop retrying (unless PermanentError is returned)
	b.MaxElapsedTime = 0
	return b
}
