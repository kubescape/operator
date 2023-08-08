package utils

import (
	"context"

	"github.com/armosec/armoapi-go/apis"
	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
)

// Commands list of commands received from websocket
type SessionObj struct {
	Command  apis.Command          `json:"command"`
	Reporter reporterlib.IReporter `json:"reporter"`
	ErrChan  chan error            `json:"-"`
}

// CredStruct holds the various credentials needed to do login into CA BE
type CredStruct struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Customer string `json:"customer"`
}

type Job struct {
	ctx        context.Context
	sessionObj SessionObj
}

func (j *Job) GetContext() context.Context {
	return j.ctx
}

func (j *Job) GetObj() SessionObj {
	return j.sessionObj
}

func (j *Job) SetContext(ctx context.Context) {
	j.ctx = ctx
}

func (j *Job) SetObj(sessionObj SessionObj) {
	j.sessionObj = sessionObj
}
