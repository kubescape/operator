package servicehandler

import (
	"flag"
	"fmt"
	"time"

	"github.com/kubescape/operator/servicehandler/extractor"
	"github.com/kubescape/operator/servicehandler/scanner"
)

const (
	Timeout = time.Second * 20
)

var namespaceFilter = scanner.Set{"kube-system": {}}
var protocolFilter = scanner.Set{"UDP": {}}

func scanTimeOutWarpper(service extractor.ServiceAddress, protocolFilter scanner.Set, scanCounter chan bool) {
	chTime := make(chan bool, 1)

	go func() {
		scanner.Scan(service, protocolFilter)
		chTime <- true
	}()

	select {
	case result := <-chTime:
		scanCounter <- result
	case <-time.After(Timeout):
		scanCounter <- false
	}
}

func ScanMain() {

	//Q: how the operator passes the cluster config?
	c := flag.Bool("c", false, "a boolean flag")
	flag.Parse()
	fmt.Println("getting config...")

	cluster_client := extractor.GetClient(*c)
	services_list := extractor.ServiceExtractor(cluster_client)

	filterd_service_list := []extractor.ServiceAddress{}
	for _, service := range services_list {
		if !namespaceFilter.Contains(service.NS) {
			filterd_service_list = append(filterd_service_list, service)

		}
	}

	scannerCounter := make(chan bool, len(filterd_service_list))
	for _, service := range filterd_service_list {
		go scanTimeOutWarpper(service, protocolFilter, scannerCounter)
	}

	for i := 0; i < len(filterd_service_list); i++ {
		<-scannerCounter
	}
}
