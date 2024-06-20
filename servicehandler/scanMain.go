package servicehandler

import (
	"context"
	"fmt"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape-network-scanner/cmd"
)

// var namespaceFilter = scanner.Set{"kube-system": {}}
var listOptions = metav1.ListOptions{
	FieldSelector: "metadata.namespace!=kube-system",
}

var protocolFilter = []string{"UDP"}

type AuthServicre struct {
	Name          string
	Namespace     string
	Service       string
	AddressesScan []AddressScan
}

type AddressScan struct {
	Ip                string
	Port              int
	Protocol          string
	SessionLayer      string
	PresentationLayer string
	ApplicationLayer  string
	Authenticated     bool
}

func (as *AddressScan) ScanAddress(ctx context.Context) {
	result, err := cmd.ScanTargets(ctx, as.Ip, as.Port)
	if err != nil {
		fmt.Printf("address: %s:%v | failed to scan", as.Ip, as.Port)
	}

	if result.ApplicationLayer == "" {
		result.ApplicationLayer = "Unknown"
		result.IsAuthenticated = true
	}

	as.ApplicationLayer = result.ApplicationLayer
	as.PresentationLayer = result.PresentationLayer
	as.SessionLayer = result.SessionLayer
	as.Authenticated = result.IsAuthenticated

}

func DiscoveryServiceHandler(ctx context.Context, kubeClient *k8sinterface.KubernetesApi) {

	//Q: how the operator passes the cluster config?
	// get a list of all  services in the cluster
	services, err := kubeClient.KubernetesClient.CoreV1().Services("").List(context.TODO(), listOptions)
	if err != nil {
		//Q: what is the error handling strategy?
		return
	}

	for _, service := range services.Items {
		authService := AuthServicre{
			Name:      fmt.Sprintf("%s@authentication", service.Name),
			Namespace: service.Namespace,
		}
		//Q: how we going to handle headless service? we need to check each pod seperetly?
		ip := service.Spec.ClusterIP

		//there is a default port
		for _, port := range service.Spec.Ports {
			fmt.Println(authService.Namespace, authService.Service, port.Port, port.Protocol)
			if slices.Contains(protocolFilter, string(port.Protocol)) {
				continue
			}

			go func() {
				addressScan := AddressScan{
					Ip:       ip,
					Port:     int(port.Port),
					Protocol: string(port.Protocol),
				}

				addressScan.ScanAddress(ctx)
				authService.AddressesScan = append(authService.AddressesScan, addressScan)
				fmt.Println(authService)
			}()

		}

	}

	kubeClient.DynamicClient.Resource(schema.GroupVersionResource{
		Group:    "kubescape.io",
		Version:  "v1",
		Resource: "servicesscanresults",
	}).Apply(context.TODO(), "ServiceScanResult", &unstructured.Unstructured{}, metav1.ApplyOptions{})

}
