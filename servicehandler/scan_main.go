package servicehandler

import (
	"flag"
	"fmt"
	"sync"

	"github.com/kubescape/kubescape-network-scanner/cmd"
	"github.com/kubescape/operator/servicehandler/extractor"
	"github.com/kubescape/operator/servicehandler/scanner"
)

var namespaceFilter = scanner.Set{"kube-system": {}}
var protocolFilter = scanner.Set{"UDP": {}}

func ScanMain(inCluster bool) {

	//Q: how the operator passes the cluster config?
	c := flag.Bool("c", inCluster, "a boolean flag")
	flag.Parse()
	fmt.Println("getting config...")

	// getting the cluster config
	cluster_client := extractor.GetClient(*c)
	// get a list of all services in the cluster
	services_list := extractor.ServiceExtractor(cluster_client)

	filterd_service_list := []extractor.ServiceAddress{}
	// filter out services in mentioned namespaces
	for _, service := range services_list {
		if !namespaceFilter.Contains(service.NS) {
			filterd_service_list = append(filterd_service_list, service)
		}
	}

	// for each service start scanning his adresses
	var wg sync.WaitGroup
	//TODO: add a result colector for all addres scan results
	//IDEA: eaach service is a go routine that waits to get all its addreses and than return results to passed channel
	results := make(chan cmd.DiscoveryResult, len(filterd_service_list))
	for _, service := range filterd_service_list {
		wg.Add(1)

		scanner.ScanService(results, service, protocolFilter)
		wg.Done()
	}
	wg.Wait()
}
