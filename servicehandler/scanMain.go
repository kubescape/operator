package servicehandler

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/k8s-interface/k8sinterface"
)

// var namespaceFilter = scanner.Set{"kube-system": {}}
var listOptions = metav1.ListOptions{
	FieldSelector: "metadata.namespace!=kube-system",
}

var protocolFilter = []string{"UDP"}

func DiscoveryServiceHandler(kubeClient *k8sinterface.KubernetesApi) {

	//Q: how the operator passes the cluster config?
	// get a list of all services in the cluster
	services, err := kubeClient.KubernetesClient.CoreV1().Services("").List(context.TODO(), listOptions)
	if err != nil {
		//Q: what is the error handling strategy?
		return
	}

	for _, service := range services.Items {
		fmt.Println(service.Name, service.Namespace)
	}

	// // for each service start scanning his adresses
	// servicesScanResults := make(map[string][]scanner.ScanResult)
	// for _, service := range filterdServiceList {
	// 	service_result := scanner.ScanService(service, protocolFilter)
	// 	servicesScanResults[service.Name] = service_result
	// }

	// authservicecrdhandler.(servicesScanResults)

}
