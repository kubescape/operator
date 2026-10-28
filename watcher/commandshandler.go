package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/backend/pkg/command"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
)

type OperatorCommandsHandler struct {
	ctx  context.Context
	pool *ants.PoolWithFunc

	k8sAPI          *k8sinterface.KubernetesApi
	commands        chan v1alpha1.OperatorCommand
	commandsWatcher *CommandWatchHandler
	config          config.IConfig
}

func NewOperatorCommandsHandler(ctx context.Context, pool *ants.PoolWithFunc, k8sAPI *k8sinterface.KubernetesApi, commandsWatcher *CommandWatchHandler, config config.IConfig) *OperatorCommandsHandler {
	handler := &OperatorCommandsHandler{
		pool:            pool,
		ctx:             ctx,
		k8sAPI:          k8sAPI,
		commands:        make(chan v1alpha1.OperatorCommand, 100),
		commandsWatcher: commandsWatcher,
		config:          config,
	}
	// The startup list can be processed as soon as CommandWatch starts. Register
	// before its goroutine launches so unfinished commands are not dropped.
	commandsWatcher.RegisterForCommands(handler.commands)
	return handler
}

func (ch *OperatorCommandsHandler) Start() {
	logger.L().Info("starting OperatorCommandsHandler")

	for {
		select {
		case cmd := <-ch.commands:
			if cmd.Spec.CommandType != string(command.OperatorCommandTypeOperatorAPI) {
				logger.L().Info("not generic command: " + cmd.Spec.CommandType)
				continue
			}
			logger.L().Debug("OperatorCommandsHandler: received command", helpers.String("guid", fmt.Sprintf("%v", cmd.Spec.GUID)))
			ch.invokeCommand(ch.ctx, cmd)
		case <-ch.ctx.Done():
			logger.L().Ctx(ch.ctx).Info("OperatorCommandsHandler: context done")
			return
		}
	}
}

func (ch *OperatorCommandsHandler) invokeCommand(ctx context.Context, opcmd v1alpha1.OperatorCommand) {
	startedAt := time.Now()
	if opcmd.Status.Started && !opcmd.Status.Completed && opcmd.Status.StartedAt != nil {
		startedAt = opcmd.Status.StartedAt.Time
	}
	var cmd apis.Command

	sessionObj := utils.NewSessionObj(ctx, ch.config, &cmd, "", opcmd.Spec.GUID)
	sessionObj.SetOperatorCommandDetails(&utils.OperatorCommandDetails{
		Command:   &opcmd,
		StartedAt: startedAt,
		Client:    ch.k8sAPI,
	})

	err := json.Unmarshal(opcmd.Spec.Body, &cmd)
	if err != nil {
		sessionObj.SetOperatorCommandStatus(ctx, utils.WithError(err))
		return
	}
	sessionObj.ParentJobID = cmd.JobTracking.ParentID
	l := utils.Job{}
	l.SetContext(ctx)
	l.SetObj(*sessionObj)

	// invoke the job - status will be updated in the job
	if err := ch.pool.Invoke(l); err != nil {
		logger.L().Ctx(ctx).Error("failed to invoke job", helpers.String("ID", cmd.GetID()), helpers.String("command", fmt.Sprintf("%v", cmd)), helpers.Error(err))
	}
}
