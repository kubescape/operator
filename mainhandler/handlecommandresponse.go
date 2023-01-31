package mainhandler

import (
	"context"
	"time"
)

type HandleCommandResponseCallBack func(ctx context.Context, payload interface{}) (bool, *time.Duration)

const (
	MaxLimitationInsertToCommandResponseChannelGoRoutine = 10
)

const (
	KubescapeResponse string = "KubescapeResponse"
)

type CommandResponseData struct {
	commandName                        string
	isCommandResponseNeedToBeRehandled bool
	nextHandledTime                    *time.Duration
	handleCallBack                     HandleCommandResponseCallBack
	payload                            interface{}
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
	timer := time.NewTimer(*data.nextHandledTime)
	*commandResponseChannel.limitedGoRoutinesCommandResponseChannel <- &timerData{
		timer:   timer,
		payload: data,
	}
}

func (mainHandler *MainHandler) waitFroTimer(data *timerData) {
	<-data.timer.C
	*mainHandler.commandResponseChannel.commandResponseChannel <- data.payload.(*CommandResponseData)
}

func (mainHandler *MainHandler) handleLimitedGoroutineOfCommandsResponse() {
	for {
		tData := <-*mainHandler.commandResponseChannel.limitedGoRoutinesCommandResponseChannel
		mainHandler.waitFroTimer(tData)
	}
}

func (mainHandler *MainHandler) createInsertCommandsResponseThreadPool() {
	for i := 0; i < MaxLimitationInsertToCommandResponseChannelGoRoutine; i++ {
		go mainHandler.handleLimitedGoroutineOfCommandsResponse()
	}
}

func (mainHandler *MainHandler) handleCommandResponse(ctx context.Context) {
	mainHandler.createInsertCommandsResponseThreadPool()
	for {
		data := <-*mainHandler.commandResponseChannel.commandResponseChannel
		data.isCommandResponseNeedToBeRehandled, data.nextHandledTime = data.handleCallBack(ctx, data.payload)
		if data.isCommandResponseNeedToBeRehandled {
			insertNewCommandResponseData(mainHandler.commandResponseChannel, data)
		}
	}
}
