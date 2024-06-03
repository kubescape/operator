package servicehandler

import (
	"flag"
	"fmt"

	"github.com/kubescape/operator/servicehandler/extractor"
	"github.com/kubescape/operator/servicehandler/scanner"
)

var namespaceFilter = scanner.Set{"kube-system": {}}
var protocolFilter = scanner.Set{"UDP": {}}

func ScanMain() {

	//Q: how the operator passes the cluster config?
	c := flag.Bool("c", true, "a boolean flag")
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

	for _, service := range filterd_service_list {
		scanner.Scan(service, protocolFilter)

	}
}
