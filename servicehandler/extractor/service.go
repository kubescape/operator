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

type address struct {
	Ip       string
	Port     int
	Protocol string
}

type ServiceAddress struct {
	NS        string
	Name      string
	Addresses []address
}

func (s ServiceAddress) String() string {
	result := fmt.Sprintf("Name: %s\n", s.Name)
	result += "Addresses:\n"
	for _, addr := range s.Addresses {
		result += fmt.Sprintf("%s : %s:%d\n", addr.Protocol, addr.Ip, addr.Port)

	}
	return result + "\n"
}

func __addresses_extractor(services *corev1.ServiceList) []ServiceAddress {
	// get an ServiceList kube object and extract from each service item the port and ip and create an servcieAddr object
	servicesList := []ServiceAddress{}
	for _, svc := range services.Items {
		var addresses []address
		name := svc.Name
		ip := svc.Spec.ClusterIP

		// there is  a possibality there is more than one open port for an ip
		for _, port := range svc.Spec.Ports {
			var addr = address{
				Ip:       ip,
				Port:     int(port.Port),
				Protocol: string(port.Protocol),
			}

			addresses = append(addresses, addr)

		}
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
	services_list := __addresses_extractor(services)

	return services_list
}
