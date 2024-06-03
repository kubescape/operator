package scanner

import (
	"fmt"

	"github.com/kubescape/kubescape-network-scanner/cmd"
	"github.com/kubescape/operator/servicehandler/extractor"
)

type Set map[string]struct{}

func (s Set) Contains(value string) bool {
	_, exists := s[value]
	return exists
}

func Scan(service extractor.ServiceAddress, filter Set) {
	for _, addres := range service.Addresses {

		if filter != nil && filter.Contains(addres.Protocol) {
			continue
		}

		result, err := cmd.ScanTargets(addres.Ip, addres.Port)

		fmt.Printf("namespace: %s\n service:%s\n the address is %s:%v is application: %s  | authenticate: %t | error: %s \n ", service.NS, service.Name, addres.Ip, addres.Port, result.ApplicationLayer, result.IsAuthenticated, err)

	}

}
