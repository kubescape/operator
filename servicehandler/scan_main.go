package servicehandler

import (
	"flag"
	"fmt"

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

	test_list := []string{}
	for _, service := range services_list {
		//filter out non-relevant protocols
		for _, address := range service.Addresses {
			//filter out non-relevant protocols
			if address.Protocol == "UDP" {
				fmt.Println(address.Protocol, " - bad protocol , skipping")
				continue
			}
			test_list = append(test_list, fmt.Sprintf("%s  %s:%v", service.Name, address.Ip, address.Port))
		}
	}
	fmt.Println(test_list)

	filterd_service_list := []extractor.ServiceAddress{}
	// filter out services in mentioned namespaces
	for _, service := range services_list {
		if !namespaceFilter.Contains(service.NS) {
			filterd_service_list = append(filterd_service_list, service)
		}
	}

	// for each service start scanning his adresses
	for _, service := range filterd_service_list {

		fmt.Printf("scanned service:%s | namespace:%s \n", service.Name, service.NS)
		scanner.ScanService(service, protocolFilter)
	}
}
