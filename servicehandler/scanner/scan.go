package scanner

import (
	"context"
	"fmt"
	"slices"
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

type ScanResult struct {
	Ip                string
	Port              int
	Protocol          string
	SessionLayer      string
	PresentationLayer string
	ApplicationLayer  string
	Authenticated     bool
}

func ScanService(service extractor.ServiceAddress, filter Set) []ScanResult {
	slices.Contains([]string{"TCP", "UDP"}, "TCP")
	// For each address in the service start a scan
	serviceResults := []ScanResult{}
	for _, address := range service.Addresses {
		addr := address
		// Filter out non-relevant protocols
		if filter != nil && filter.Contains(addr.Protocol) {
			fmt.Printf("service: %s | address %s:%v | bad protocol - %s skipping ", service.Name, address.Ip, address.Port, address.Protocol)
			continue
		}

		ctx := context.Background()
		go func(ctx context.Context, address extractor.Address) {
			result, err := cmd.ScanTargets(ctx, address.Ip, address.Port)
			if err != nil {
				fmt.Printf("service: %s | address: %s:%v | failed to scan", service.Name, address.Ip, address.Port)
				serviceResults = append(serviceResults, ScanResult{})
			} else {
				fmt.Printf("service: %s | address: %s:%v | is auth : %v | application: %s \n", service.Name, address.Ip, address.Port, result.IsAuthenticated, result.ApplicationLayer)

				// Append the scan result to the ServiceResult
				scanResult := ScanResult{
					Ip:                address.Ip,
					Port:              address.Port,
					Protocol:          address.Protocol,
					SessionLayer:      result.SessionLayer,
					PresentationLayer: result.PresentationLayer,
					ApplicationLayer:  result.ApplicationLayer,
					Authenticated:     result.IsAuthenticated,
				}
				serviceResults = append(serviceResults, scanResult)
			}
		}(ctx, addr)
	}

	// Return the populated ServiceResult
	return serviceResults
}
