package servicehandler

import (
	"context"
	"slices"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape-network-scanner/cmd"

	logger "github.com/kubescape/go-logger"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"
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

type currentServiceList map[string]ServicreAuthenticaion

type ServicreAuthenticaion struct {
	client    dynamic.ResourceInterface
	ctx       context.Context
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

func (sr ServicreAuthenticaion) Unstructured() *unstructured.Unstructured {

	k8sruntime.DefaultUnstructuredConverter.ToUnstructured(ServicreAuthenticaion{})
	unstructedService := make(map[string]interface{})
	unstructedService["kind"] = kind
	unstructedService["apiVersion"] = apiVersion

	unstructedService["metadata"] = map[string]interface{}{
		"name": sr.name,
	}
	unstructedService["spec"] = map[string]interface{}{
		"clusterIP": sr.clusterIP,
		"ports":     []map[string]interface{}{},
	}
	var portsSlice []map[string]interface{}
	for _, port := range sr.ports {
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

func (sr *ServicreAuthenticaion) initialPorts(ports []v1.ServicePort) {
	sr.ports = make([]Port, 0, len(ports))
	for _, port := range ports {
		sr.ports = append(sr.ports, Port{
			port:     int(port.Port),
			protocol: string(port.Protocol),
		})
	}
}

func (sr *ServicreAuthenticaion) Scan() {

	portsScanWg := sync.WaitGroup{}
	for _, pr := range sr.ports {
		portsScanWg.Add(1)
		if slices.Contains(protocolFilter, string(pr.protocol)) {
			continue
		}

		go func(pr Port) {
			pr.scanPort(sr.ctx, sr.clusterIP)
			sr.ports = append(sr.ports, pr)
			portsScanWg.Done()
		}(pr)

	}
	portsScanWg.Wait()

	_, err := sr.client.Apply(context.TODO(), sr.name, sr.Unstructured(), metav1.ApplyOptions{FieldManager: FieldManager})
	if err != nil {
		logger.L().Ctx(sr.ctx).Error(err.Error())
	}

}

func (sra ServicreAuthenticaion) Delete() {
	err := sra.client.Delete(context.TODO(), sra.name, metav1.DeleteOptions{})
	if err != nil {
		logger.L().Ctx(sra.ctx).Error(err.Error())
	}
}

func (port *Port) scanPort(ctx context.Context, ip string) {
	result, err := cmd.ScanTargets(ctx, ip, port.port)
	if err != nil {
		logger.L().Ctx(ctx).Error(err.Error())
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
func (csl currentServiceList) deleteServices(kubeClient *k8sinterface.KubernetesApi) {
	logger.L().Info("Deleting services that are not in the current list")
	auhtServices, err := kubeClient.DynamicClient.Resource(Schema).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return
	}

	for _, service := range auhtServices.Items {
		if _, ok := csl[service.GetName()]; !ok {
			//delete the service
			csl[service.GetName()].Delete()
		}

	}
}

func DiscoveryServiceHandler(ctx context.Context, kubeClient *k8sinterface.KubernetesApi, timeout time.Duration) {
	for {
		currentServiceList := make(currentServiceList)

		// get a list of all  services in the cluster
		services, err := kubeClient.KubernetesClient.CoreV1().Services("").List(context.TODO(), serviceListOptions)
		if err != nil {
			logger.L().Ctx(ctx).Error(err.Error())
			return
		}

		//Q: how we going to handle headless service? we need to check each pod seperetly?
		for _, service := range services.Items {
			sra := ServicreAuthenticaion{
				client:    kubeClient.DynamicClient.Resource(Schema).Namespace(service.Namespace),
				name:      service.Name,
				namespace: service.Namespace,
				clusterIP: service.Spec.ClusterIP,
			}

			currentServiceList[sra.name] = sra
			sra.initialPorts(service.Spec.Ports)
			sra.Scan()
		}
		currentServiceList.deleteServices(kubeClient)

		time.Sleep(timeout)
	}

}
