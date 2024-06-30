package servicehandler

import (
	"context"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape-network-scanner/cmd"
)

type Port struct {
	port              int
	protocol          string
	sessionLayer      string
	presentationLayer string
	applicationLayer  string
	authenticated     bool
}

func (port *Port) scan(ctx context.Context, ip string) {
	result, err := cmd.ScanTargets(ctx, ip, port.port)
	port.applicationLayer = result.ApplicationLayer
	port.presentationLayer = result.PresentationLayer
	port.sessionLayer = result.SessionLayer
	port.authenticated = result.IsAuthenticated

	if result.ApplicationLayer == "" {
		// if we can't get the application layer, then we change to Unknown
		port.authenticated = true
	}

	if err != nil {
		//if we have an error, we log it and set all layers to Unknown
		logger.L().Ctx(ctx).Error(err.Error())
		port.applicationLayer = "failed_to_scan"
		port.authenticated = false
	}
}
