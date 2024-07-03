package servicehandler

import (
	"context"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape-network-scanner/cmd"
	v1 "k8s.io/api/core/v1"
)

type Port struct {
	port              int
	protocol          string
	sessionLayer      string
	presentationLayer string
	applicationLayer  string
	authenticated     *bool
}

func (port *Port) scan(ctx context.Context, ip string) {
	result, err := cmd.ScanTargets(ctx, ip, port.port)
	if err != nil {
		logger.L().Ctx(ctx).Error(err.Error())
		return
	}

	port.applicationLayer = result.ApplicationLayer
	port.presentationLayer = result.PresentationLayer
	port.sessionLayer = result.SessionLayer
	if result.ApplicationLayer != "" {
		port.authenticated = &result.IsAuthenticated
	}
}

func K8sPortsTranslator(sp []v1.ServicePort) []Port {
	ports := make([]Port, 0, len(sp))
	for _, port := range sp {
		ports = append(ports,
			Port{
				port:     int(port.Port),
				protocol: string(port.Protocol),
			})
	}
	return ports
}
