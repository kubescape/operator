package scanner

import (
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

func ScanService(service extractor.ServiceAddress, filter Set) {
	for _, address := range service.Addresses {
		//filter out non-relevant protocols
		if filter != nil && filter.Contains(address.Protocol) {
			fmt.Println(address.Protocol, " - bad protocol , skipping")
			continue
		}

		ch := make(chan struct{})
		fmt.Printf("Debug -> creating channel %p \n", &ch)

		go func() {

			timer := time.After(Timeout)
			result, err := cmd.ScanTargets(address.Ip, address.Port)
			if err == nil {
				fmt.Println(service.Name, result.ApplicationLayer, result.IsAuthenticated, result.Properties)
			} else {

				fmt.Println(err)
			}

			select {
			case <-timer:
				fmt.Printf(service.Name+" | %s:%v |Timeout \n", address.Ip, address.Port)
				return
			default:
				go func() {

				}()
				fmt.Printf(service.Name+" | %s:%v |finished scan succefully address \n", address.Ip, address.Port)

			}
		}()

		fmt.Printf("Debug -> %s:%v waiting for an answer(timeout/result) \n", address.Ip, address.Port)

	}
}

// func ScanService(service extractor.ServiceAddress, filter Set) {
// 	var wg sync.WaitGroup
// 	for _, address := range service.Addresses {
// 		//filter out non-relevant protocols
// 		if filter != nil && filter.Contains(address.Protocol) {
// 			fmt.Println(address.Protocol, " - bad protocol , skipping")
// 			continue
// 		}

// 		//add 1 to the waitingGroup counter for each scanned address
// 		wg.Add(1)

// 		defer wg.Done()
// 		ctx, cancel := context.WithTimeout(context.Background(), Timeout)
// 		defer cancel()

// 		fmt.Printf("Debug -> creating context %p \n", &ctx)
// 		ch := make(chan struct{})
// 		fmt.Printf("Debug -> creating channel %p \n", &ch)
// 		go func() {
// 			fmt.Printf("start scanning : %s %s:%v \n", service.Name, address.Ip, address.Port)
// 			result, err := cmd.ScanTargets(address.Ip, address.Port)

// 			if err == nil {
// 				fmt.Println(service.Name, result.ApplicationLayer, result.IsAuthenticated, result.Properties)
// 			} else {

// 				fmt.Println(err)
// 			}
// 			close(ch)
// 		}()
// 		fmt.Printf("Debug -> %s:%v waiting for an answer(timeout/result) \n", address.Ip, address.Port)
// 		select {
// 		case <-ctx.Done():
// 			fmt.Printf("Got Timeout - service: %s | address: %s:%v\n ", service.Name, address.Ip, address.Port)
// 			return
// 		case <-ch:
// 			fmt.Printf(service.Name+" | %s:%v |finished scan succefully address \n", address.Ip, address.Port)
// 			return
// 		}

// 	}
// 	wg.Wait()
// }
