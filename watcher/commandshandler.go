package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/armosec/armoapi-go/apis"
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
	return &OperatorCommandsHandler{
		pool:            pool,
		ctx:             ctx,
		k8sAPI:          k8sAPI,
		commands:        make(chan v1alpha1.OperatorCommand, 100),
		commandsWatcher: commandsWatcher,
		config:          config,
	}
}

func (ch *OperatorCommandsHandler) Start() {
	logger.L().Info("starting OperatorCommandsHandler")
	ch.commandsWatcher.RegisterForCommands(ch.commands)

	for {
		select {
		case cmd := <-ch.commands:
			if cmd.Spec.CommandType != "OperatorAPI" {
				logger.L().Info("not generic command" + cmd.Spec.CommandType)
				continue
			}
			ch.invokeCommand(ch.ctx, cmd)
		case <-ch.ctx.Done():
			logger.L().Ctx(ch.ctx).Info("RegistryCommandsHandler: context done")
			return
		}
	}
}

func (ch *OperatorCommandsHandler) invokeCommand(ctx context.Context, opcmd v1alpha1.OperatorCommand) {
	startedAt := time.Now()
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
	l := utils.Job{}
	l.SetContext(ctx)
	l.SetObj(*sessionObj)

	// invoke the job - status will be updated in the job
	if err := ch.pool.Invoke(l); err != nil {
		logger.L().Ctx(ctx).Error("failed to invoke job", helpers.String("ID", cmd.GetID()), helpers.String("command", fmt.Sprintf("%v", cmd)), helpers.Error(err))
	}
}
