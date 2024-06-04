package extractor

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var UDP = "UDP"
var TCP = "TCP"

type Address struct {
	Ip       string
	Port     int
	Protocol string
}

type ServiceAddress struct {
	NS        string
	Name      string
	Addresses []Address
}

func (s ServiceAddress) String() string {
	result := fmt.Sprintf("Name: %s\n", s.Name)
	result += "Addresses:\n"
	for _, addr := range s.Addresses {
		result += fmt.Sprintf("%s-%s:%d", addr.Protocol, addr.Ip, addr.Port)

	}
	return result + "\n"
}

func addressesExtractor(services *corev1.ServiceList) []ServiceAddress {
	// get an ServiceList kube object and extract from each service it addresses
	servicesList := []ServiceAddress{}
	for _, svc := range services.Items {
		var addresses []Address
		name := svc.Name
		ip := svc.Spec.ClusterIP

		// there is a possibality there is more than one open port for an address
		for _, port := range svc.Spec.Ports {
			var addr = Address{
				Ip:       ip,
				Port:     int(port.Port),
				Protocol: string(port.Protocol),
			}

			addresses = append(addresses, addr)

		}
		//assign service object with it addreses
		service := ServiceAddress{Name: name, Addresses: addresses, NS: svc.Namespace}

		servicesList = append(servicesList, service)

	}
	return servicesList

}

func ServiceExtractor(clientset *kubernetes.Clientset) []ServiceAddress {

	services, err := clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic("canntot extarct services")
	}
	services_list := addressesExtractor(services)

	return services_list
}
