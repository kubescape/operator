package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/kubescape/kubescape-network-scanner/cmd"
	"github.com/kubescape/operator/servicehandler/extractor"
)

const (
	Timeout = time.Second * 15
)

// Set object with contains method for filtering functionality
type Set map[string]struct{}

func (s Set) Contains(value string) bool {
	_, exists := s[value]
	return exists
}

func ScanService(resultsChan chan cmd.DiscoveryResult, service extractor.ServiceAddress, filter Set) {

	for _, address := range service.Addresses {
		//filter out non-relevant protocols
		if filter != nil && filter.Contains(address.Protocol) {
			fmt.Printf("service: %s | address %s:%v | bad protocol - %s skipping ", service.Name, address.Ip, address.Port, address.Protocol)
			continue
		}

		ctx, _ := context.WithTimeout(context.Background(), Timeout)
		go func(context.Context) {
			result, err := cmd.ScanTargets(ctx, address.Ip, address.Port)

			if err != nil {
				fmt.Printf("service: %s | address: %s:%v | failed to scan", service.Name, address.Ip, address.Port)
			} else {
				fmt.Printf("service: %s | address: %s:%v | is auth : %v | application: %s \n", service.Name, address.Ip, address.Port, result.IsAuthenticated, result.ApplicationLayer)

			}
		}(ctx)
	}

}
