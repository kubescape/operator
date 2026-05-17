package watcher

import (
	"context"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

// ListFunc is a function that lists resources with paging.
type ListFunc[T runtime.Object] func(ctx context.Context, opts metav1.ListOptions) ([]T, string, string, error)

// IDAndChecksumFunc extracts a unique ID and a checksum/version from a resource.
type IDAndChecksumFunc[T runtime.Object] func(obj T) (id string, checksum string)

// EventHandlerFunc handles events for a resource.
type EventHandlerFunc[T runtime.Object] func(eventQueue *CooldownQueue, producedCommands chan<- *apis.Command, errorCh chan<- error)

// GenericResourceWatch is a generic periodic watcher for any resource type implementing metav1.Object.
func GenericResourceWatch[T runtime.Object](ctx context.Context, cfg config.IConfig, workerPool *ants.PoolWithFunc, listFunc ListFunc[T], eventHandler EventHandlerFunc[T]) {
	eventQueue := NewCooldownQueueWithParams(15*time.Second, 1*time.Second)
	cmdCh := make(chan *apis.Command)
	errorCh := make(chan error)

	go eventHandler(eventQueue, cmdCh, errorCh)

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	var since string
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var continueToken string
			for {
				logger.L().Debug("GenericResourceWatch - listing resources", helpers.String("continueToken", continueToken), helpers.String("since", since))
				items, nextToken, lastUpdated, err := listFunc(ctx, metav1.ListOptions{
					Limit:           int64(100),
					Continue:        continueToken,
					ResourceVersion: since, // ensure we only get changes since the last check
				})
				if err != nil {
					logger.L().Ctx(ctx).Error("GenericResourceWatch - error in listFunc", helpers.Error(err))
					break
				}
				for _, obj := range items {
					// added and modified events are treated the same, so we enqueue a Modified event for both
					eventQueue.Enqueue(watch.Event{Type: watch.Modified, Object: obj})
				}
				since = lastUpdated
				if nextToken == "" {
					break
				}
				continueToken = nextToken
			}
		case cmd, ok := <-cmdCh:
			if ok {
				_ = utils.AddCommandToChannel(ctx, cfg, cmd, workerPool)
			}
		case err, ok := <-errorCh:
			if ok {
				logger.L().Ctx(ctx).Error("GenericResourceWatch - error from errorCh", helpers.Error(err))
			}
		}
	}
}
