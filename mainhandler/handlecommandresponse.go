package mainhandler

import (
	"context"
	"time"

	"github.com/kubescape/operator/config"
)

type HandleCommandResponseCallBack func(ctx context.Context, config config.IConfig, payload interface{}) (bool, *time.Duration)

const (
	MaxLimitationInsertToCommandResponseChannelGoRoutine = 10
)

const (
	KubescapeResponse string = "KubescapeResponse"
)

type CommandResponseData struct {
	payload                            interface{}
	nextHandledTime                    *time.Duration
	handleCallBack                     HandleCommandResponseCallBack
	commandName                        string
	isCommandResponseNeedToBeRehandled bool
}

type timerData struct {
	timer   *time.Timer
	payload interface{}
}

type commandResponseChannelData struct {
	commandResponseChannel                  *chan *CommandResponseData
	limitedGoRoutinesCommandResponseChannel *chan *timerData
}

func createNewCommandResponseData(commandName string, cb HandleCommandResponseCallBack, payload interface{}, nextHandledTime *time.Duration) *CommandResponseData {
	return &CommandResponseData{
		commandName:     commandName,
		handleCallBack:  cb,
		payload:         payload,
		nextHandledTime: nextHandledTime,
	}
}

func insertNewCommandResponseData(commandResponseChannel *commandResponseChannelData, data *CommandResponseData) {
	insertNewCommandResponseDataWithContext(context.Background(), commandResponseChannel, data)
}

func insertNewCommandResponseDataWithContext(ctx context.Context, commandResponseChannel *commandResponseChannelData, data *CommandResponseData) {
	if commandResponseChannel == nil || data == nil || data.nextHandledTime == nil {
		return
	}
	timer := time.NewTimer(*data.nextHandledTime)
	select {
	case <-ctx.Done():
		timer.Stop()
	case *commandResponseChannel.limitedGoRoutinesCommandResponseChannel <- &timerData{
		timer:   timer,
		payload: data,
	}:
	}
}

func (mainHandler *MainHandler) waitFroTimer(ctx context.Context, data *timerData) {
	if data == nil || data.timer == nil {
		return
	}
	defer data.timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-data.timer.C:
	}
	select {
	case <-ctx.Done():
	case *mainHandler.commandResponseChannel.commandResponseChannel <- data.payload.(*CommandResponseData):
	}
}

func (mainHandler *MainHandler) handleLimitedGoroutineOfCommandsResponse(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case tData := <-*mainHandler.commandResponseChannel.limitedGoRoutinesCommandResponseChannel:
			mainHandler.waitFroTimer(ctx, tData)
		}
	}
}

func (mainHandler *MainHandler) createInsertCommandsResponseThreadPool(ctx context.Context) {
	for i := 0; i < MaxLimitationInsertToCommandResponseChannelGoRoutine; i++ {
		go mainHandler.handleLimitedGoroutineOfCommandsResponse(ctx)
	}
}

func (mainHandler *MainHandler) HandleCommandResponse(ctx context.Context) {
	mainHandler.createInsertCommandsResponseThreadPool(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-*mainHandler.commandResponseChannel.commandResponseChannel:
			if data == nil || data.handleCallBack == nil {
				continue
			}
			data.isCommandResponseNeedToBeRehandled, data.nextHandledTime = data.handleCallBack(ctx, mainHandler.config, data.payload)
			if data.isCommandResponseNeedToBeRehandled {
				insertNewCommandResponseDataWithContext(ctx, mainHandler.commandResponseChannel, data)
			}
		}
	}
}
