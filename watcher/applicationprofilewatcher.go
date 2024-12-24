package watcher

import (
	"context"
	"fmt"
	"time"

	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// ApplicationProfileWatch watches and processes changes on ApplicationProfile resources
func (wh *WatchHandler) ApplicationProfileWatch(ctx context.Context, workerPool *ants.PoolWithFunc) {
	inputEvents := make(chan watch.Event)
	cmdCh := make(chan *apis.Command)
	errorCh := make(chan error)
	apEvents := make(<-chan watch.Event)

	// The watcher is considered unavailable by default
	apWatcherUnavailable := make(chan struct{})
	go func() {
		apWatcherUnavailable <- struct{}{}
	}()

	go wh.HandleApplicationProfileEvents(inputEvents, cmdCh, errorCh)

	// notifyWatcherDown notifies the appropriate channel that the watcher
	// is down and backs off for the retry interval to not produce
	// unnecessary events
	notifyWatcherDown := func(watcherDownCh chan<- struct{}) {
		go func() { watcherDownCh <- struct{}{} }()
		time.Sleep(retryInterval)
	}

	var watcher watch.Interface
	var err error
	for {
		select {
		case apEvent, ok := <-apEvents:
			if ok {
				inputEvents <- apEvent
			} else {
				notifyWatcherDown(apWatcherUnavailable)
			}
		case cmd, ok := <-cmdCh:
			if ok {
				utils.AddCommandToChannel(ctx, wh.cfg, cmd, workerPool)
			} else {
				notifyWatcherDown(apWatcherUnavailable)
			}
		case err, ok := <-errorCh:
			if ok {
				logger.L().Ctx(ctx).Error(fmt.Sprintf("error in ApplicationProfileWatch: %v", err.Error()))
			} else {
				notifyWatcherDown(apWatcherUnavailable)
			}
		case <-apWatcherUnavailable:
			if watcher != nil {
				watcher.Stop()
			}

			watcher, err = wh.getApplicationProfileWatcher()
			if err != nil {
				notifyWatcherDown(apWatcherUnavailable)
			} else {
				apEvents = watcher.ResultChan()
			}
		}
	}

}

func (wh *WatchHandler) HandleApplicationProfileEvents(sfEvents <-chan watch.Event, producedCommands chan<- *apis.Command, errorCh chan<- error) {
	defer close(errorCh)

	for e := range sfEvents {
		logger.L().Info("received application profile event", helpers.Interface("event", e))
		obj, ok := e.Object.(*spdxv1beta1.ApplicationProfile)
		if !ok {
			errorCh <- ErrUnsupportedObject
			continue
		}

		switch e.Type {
		case watch.Added:
		//
		case watch.Modified:
		//
		case watch.Deleted:
			continue
		case watch.Bookmark:
			continue
		}

		if skip, _ := utils.SkipApplicationProfile(obj.ObjectMeta.Annotations); skip {
			continue
		}

		// TODO check if we can skip processing (based on size?)

		// create command
		cmd := &apis.Command{
			Wlid:        obj.Annotations[helpersv1.WlidMetadataKey],
			CommandName: utils.CommandScanApplicationProfile,
			Args: map[string]interface{}{
				utils.ArgsName:      obj.Name,
				utils.ArgsNamespace: obj.Namespace,
			},
		}
		// send command
		logger.L().Info("scanning application profile", helpers.String("wlid", cmd.Wlid), helpers.String("name", obj.Name), helpers.String("namespace", obj.Namespace))
		producedCommands <- cmd
	}
}

func (wh *WatchHandler) getApplicationProfileWatcher() (watch.Interface, error) {
	// no need to support ExcludeNamespaces and IncludeNamespaces since node-agent will respect them as well
	return wh.storageClient.SpdxV1beta1().ApplicationProfiles("").Watch(context.Background(), v1.ListOptions{})
}
