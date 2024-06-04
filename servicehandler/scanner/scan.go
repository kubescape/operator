package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kubescape/kubescape-network-scanner/cmd"
	"github.com/kubescape/operator/servicehandler/extractor"
)

const (
	Timeout = time.Second * 10
)

// Set object with contains method for filtering functionality
type Set map[string]struct{}

func (s Set) Contains(value string) bool {
	_, exists := s[value]
	return exists
}
func scanAddress(ch chan bool, ip string, port int, name string) {

	result, err := cmd.ScanTargets(ip, port)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("service: %s | address: %s:%v| application: %s  | authenticate: %t | error: %s \n ", name, ip, port, result.ApplicationLayer, result.IsAuthenticated, err)
	}
	ch <- true
}

func ScanService(service extractor.ServiceAddress, filter Set) {
	var wg sync.WaitGroup
	for _, address := range service.Addresses {
		//filter out non-relevant protocols
		if filter != nil && filter.Contains(address.Protocol) {
			fmt.Println(address.Protocol, " - bad protocol , skipping")
			continue
		}

		fmt.Printf(service.Name+": sacanning address %s:%v  %s\n", address.Ip, address.Port, address.Protocol)
		//add 1 to the waitingGroup counter for each scanned address
		wg.Add(1)
		go func(addr extractor.Address) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), Timeout)
			defer cancel()

			ch := make(chan bool, 1)
			go scanAddress(ch, addr.Ip, addr.Port, service.Name)

			select {
			case <-ctx.Done():
				fmt.Printf("Got Timeout - service: %s | address: %s:%v\n ", service.Name, addr.Ip, addr.Port)
				return
			case <-ch:
				return
			}
		}(address)

	}
	wg.Wait()
}
