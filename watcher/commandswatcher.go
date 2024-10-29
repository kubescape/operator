package watcher

import (
	"context"
	"errors"
	"fmt"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/cenkalti/backoff"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/backend/pkg/command"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/pager"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type CommandWatchHandler struct {
	k8sAPI           *k8sinterface.KubernetesApi
	eventQueue       *CooldownQueue
	commandReceivers mapset.Set[chan v1alpha1.OperatorCommand]
}

func NewCommandWatchHandler(k8sAPI *k8sinterface.KubernetesApi) *CommandWatchHandler {
	return &CommandWatchHandler{
		k8sAPI:           k8sAPI,
		eventQueue:       NewCooldownQueue(),
		commandReceivers: mapset.NewSet[chan v1alpha1.OperatorCommand](),
	}
}

func (cwh *CommandWatchHandler) RegisterForCommands(receiver chan v1alpha1.OperatorCommand) {
	cwh.commandReceivers.Add(receiver)
}

func (cwh *CommandWatchHandler) CommandWatch(ctx context.Context) {
	// list commands and add them to the queue, this is for the commands that were created before the watch started
	cwh.listCommands(ctx)
	// start watching
	go cwh.watchRetry(ctx)

	// process events
	for event := range cwh.eventQueue.ResultChan {
		// skip non-objects
		obj, ok := event.Object.(runtime.Object)
		if !ok || obj == nil {
			continue
		}
		switch event.Type {
		case watch.Added:
			cwh.AddHandler(obj)
		}
	}
}

func (cwh *CommandWatchHandler) listCommands(ctx context.Context) {
	if err := pager.New(func(ctx context.Context, opts v1.ListOptions) (runtime.Object, error) {
		return cwh.k8sAPI.GetDynamicClient().Resource(v1alpha1.SchemaGroupVersionResource).Namespace(armotypes.KubescapeNamespace).List(context.Background(), opts)
	}).EachListItem(ctx, v1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", command.OperatorCommandAppNameLabelKey, "operator"),
	}, func(obj runtime.Object) error {
		cwh.eventQueue.Enqueue(watch.Event{
			Type:   watch.Added,
			Object: obj,
		})
		return nil
	}); err != nil {
		logger.L().Ctx(ctx).Error("failed add list of commands", helpers.Error(err))
	}
}

func (cwh *CommandWatchHandler) watchRetry(ctx context.Context) {
	watchOpts := v1.ListOptions{
		Watch:         true,
		LabelSelector: fmt.Sprintf("%s=%s", command.OperatorCommandAppNameLabelKey, "operator"),
	}
	if err := backoff.RetryNotify(func() error {
		watcher, err := cwh.k8sAPI.GetDynamicClient().Resource(v1alpha1.SchemaGroupVersionResource).Namespace(armotypes.KubescapeNamespace).Watch(context.Background(), watchOpts)
		if err != nil {
			return fmt.Errorf("failed to get commands watcher: %w", err)
		}
		for {
			event, chanActive := <-watcher.ResultChan()
			if metaObject, ok := event.Object.(resourceVersionGetter); ok {
				watchOpts.ResourceVersion = metaObject.GetResourceVersion()
			}
			if cwh.eventQueue.Closed() {
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
			cwh.eventQueue.Enqueue(event)
		}
	}, newBackOff(), func(err error, d time.Duration) {
		if !errors.Is(err, errWatchClosed) {
			logger.L().Ctx(ctx).Warning("watch", helpers.Error(err),
				helpers.String("resource", "commands"),
				helpers.String("retry in", d.String()))
		}
	}); err != nil {
		logger.L().Ctx(ctx).Fatal("giving up watch", helpers.Error(err),
			helpers.String("resource", "commands"))
	}
}

func (cwh *CommandWatchHandler) AddHandler(obj runtime.Object) {
	if un, ok := obj.(*unstructured.Unstructured); ok {
		// Convert the unstructured object to a typed object.
		cmd, err := ConvertUnstructuredToOperatorCommand(un)
		if err != nil {
			logger.L().Error("Failed to convert unstructured object to OperatorCommand", helpers.Error(err))
			return
		}

		logger.L().Info("Received command", helpers.String("command", cmd.Name), helpers.String("GUID", cmd.Spec.GUID))

		// Skip the command if it has already been processed.
		if cmd.Status.Completed {
			logger.L().Info("Command has already been processed, skipping.", helpers.String("command", cmd.Name))
			return
		}

		for receiver := range cwh.commandReceivers.Iter() {
			receiver <- *cmd
		}
	}
}

func ConvertUnstructuredToOperatorCommand(un *unstructured.Unstructured) (*v1alpha1.OperatorCommand, error) {
	cmd := &v1alpha1.OperatorCommand{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.Object, cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}
