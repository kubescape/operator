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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type resourceVersionGetter interface {
	GetResourceVersion() string
}

var errWatchClosed = errors.New("watch channel closed")

func (wh *WatchHandler) watchRetry(ctx context.Context, watchOpts metav1.ListOptions) {
	if err := backoff.RetryNotify(func() error {
		watcher, err := wh.k8sAPI.KubernetesClient.CoreV1().Pods("").Watch(context.Background(), watchOpts)
		if err != nil {
			dropGoneVersion(&watchOpts, err)
			return fmt.Errorf("client resource: %w", err)
		}
		for {
			event, chanActive := <-watcher.ResultChan()
			resumeFrom(&watchOpts, event)
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

// resumeFrom records where the next watch resumes, the way client-go's RetryWatcher does:
// at the version of the last object received, so a reconnect carries on from there, or
// from the current state when the server says that version is gone, since nothing else
// can follow it. An error event carries a Status, not an object; its empty version is not
// a place to resume, and taking it for one restarted the watch from scratch after any
// error, replaying every object.
func resumeFrom(opts *metav1.ListOptions, event watch.Event) {
	switch event.Type {
	case watch.Added, watch.Modified, watch.Deleted, watch.Bookmark:
		if metaObject, ok := event.Object.(resourceVersionGetter); ok {
			opts.ResourceVersion = metaObject.GetResourceVersion()
		}
	case watch.Error:
		dropGoneVersion(opts, apierrors.FromObject(event.Object))
	}
}

// dropGoneVersion forgets the resume version when err says the server no longer has it,
// whether the server said so in an event or by refusing the watch request itself.
func dropGoneVersion(opts *metav1.ListOptions, err error) {
	if apierrors.IsResourceExpired(err) || apierrors.IsGone(err) {
		opts.ResourceVersion = ""
	}
}

func newBackOff() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	// never stop retrying (unless PermanentError is returned)
	b.MaxElapsedTime = 0
	return b
}
