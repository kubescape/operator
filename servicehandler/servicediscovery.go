package servicehandler

import (
	"context"
	"slices"
	"sync"
	"time"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape-network-scanner/cmd"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const (
	kind         = "ServiceScanResult"
	resource     = "servicesscanresults"
	group        = "kubescape.io"
	version      = "v1"
	apiVersion   = group + "/" + version
	FieldManager = "kubescape|operator|serviceDiscoveryHandler"
)

var Schema = schema.GroupVersionResource{
	Group:    group,
	Version:  version,
	Resource: resource,
}

var serviceListOptions = metav1.ListOptions{
	FieldSelector: "metadata.namespace!=kube-system",
}

var protocolFilter = []string{"UDP"}

type currentServiceList [][2]string

func (sl currentServiceList) contains(name string, namespace string) bool {
	for _, service := range sl {
		if service[0] == name && service[1] == namespace {
			return true
		}
	}
	return false
}

type ServicreAuthenticaion struct {
	metadata  string
	name      string
	namespace string
	clusterIP string
	ports     []Port
}

type Port struct {
	port              int
	protocol          string
	sessionLayer      string
	presentationLayer string
	applicationLayer  string
	authenticated     bool
}

func (sra ServicreAuthenticaion) Unstructured() *unstructured.Unstructured {
	// a, _ := k8sruntime.DefaultUnstructuredConverter.ToUnstructured(sra)
	unstructedService := make(map[string]interface{})
	unstructedService["kind"] = kind
	unstructedService["apiVersion"] = apiVersion

	unstructedService["metadata"] = map[string]interface{}{
		"name": sra.name,
	}
	unstructedService["spec"] = map[string]interface{}{
		"clusterIP": sra.clusterIP,
		"ports":     []map[string]interface{}{},
	}
	var portsSlice []map[string]interface{}
	for _, port := range sra.ports {
		portMap := map[string]interface{}{
			"port":              port.port,
			"protocol":          port.protocol,
			"sessionLayer":      port.sessionLayer,
			"presentationLayer": port.presentationLayer,
			"applicationLayer":  port.applicationLayer,
			"authenticated":     port.authenticated,
		}
		portsSlice = append(portsSlice, portMap)
	}
	unstructedService["spec"].(map[string]interface{})["ports"] = portsSlice
	return &unstructured.Unstructured{Object: unstructedService}
}

func (sra *ServicreAuthenticaion) initialPorts(ports []v1.ServicePort) {
	sra.ports = make([]Port, 0, len(ports))
	for _, port := range ports {
		sra.ports = append(sra.ports, Port{
			port:     int(port.Port),
			protocol: string(port.Protocol),
		})
	}
}

func (sra *ServicreAuthenticaion) Scan(ctx context.Context, client dynamic.NamespaceableResourceInterface) {

	portsScanWg := sync.WaitGroup{}

	for _, pr := range sra.ports {
		portsScanWg.Add(1)
		if slices.Contains(protocolFilter, string(pr.protocol)) {
			continue
		}

		go func(pr Port) {
			pr.scanPort(ctx, sra.clusterIP)
			sra.ports = append(sra.ports, pr)
			portsScanWg.Done()
		}(pr)

	}
	portsScanWg.Wait()

	_, err := client.Namespace(sra.namespace).Apply(context.TODO(), sra.name, sra.Unstructured(), metav1.ApplyOptions{FieldManager: FieldManager})
	if err != nil {
		logger.L().Ctx(ctx).Error(err.Error())
	}
}

func (port *Port) scanPort(ctx context.Context, ip string) {
	result, err := cmd.ScanTargets(ctx, ip, port.port)
	if err != nil {
		logger.L().Ctx(ctx).Error(err.Error())
		result.ApplicationLayer = "Unknown"
		result.PresentationLayer = "Unknown"
		result.SessionLayer = "Unknown"
		result.IsAuthenticated = true
		return
	}

	if result.ApplicationLayer == "" {
		result.ApplicationLayer = "Unknown"
		result.IsAuthenticated = true
	}

	port.applicationLayer = result.ApplicationLayer
	port.presentationLayer = result.PresentationLayer
	port.sessionLayer = result.SessionLayer
	port.authenticated = result.IsAuthenticated

}
func (csl currentServiceList) deleteServices(client dynamic.NamespaceableResourceInterface) error {
	logger.L().Info("Deleting services that are not in the current list")
	auhtServices, err := client.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, service := range auhtServices.Items {
		if !csl.contains(service.GetName(), service.GetNamespace()) {
			err := client.Namespace(service.GetNamespace()).Delete(context.TODO(), service.GetName(), metav1.DeleteOptions{})
			if err != nil {
				logger.L().Error(err.Error())
			}

		}
	}
	return err
}

func DiscoveryServiceHandler(ctx context.Context, kubeClient *k8sinterface.KubernetesApi, timeout time.Duration) {
	{
		dynamicClient := kubeClient.DynamicClient.Resource(Schema)
		regularclient := kubeClient.KubernetesClient.CoreV1()

		for {
			currentServiceList := make(currentServiceList, 0)

			// get a list of all  services in the cluster
			services, err := regularclient.Services("").List(context.TODO(), serviceListOptions)
			if err != nil {
				logger.L().Ctx(ctx).Error(err.Error())
				return
			}

			//Q: how we going to handle headless service? we need to check each pod seperetly?

			for _, service := range services.Items {
				sra := ServicreAuthenticaion{
					name:      service.Name,
					namespace: service.Namespace,
					clusterIP: service.Spec.ClusterIP,
				}

				currentServiceList = append(currentServiceList, [2]string{service.Name, service.Namespace})
				sra.initialPorts(service.Spec.Ports)
				sra.Scan(ctx, dynamicClient)
			}
			currentServiceList.deleteServices(dynamicClient)

			time.Sleep(timeout)
		}

	}
}
