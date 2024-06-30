package servicehandler

import (
	"context"
	"slices"
	"sync"
	"time"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/panjf2000/ants/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	kind         = "ServiceScanResult"
	resource     = "servicesscanresults"
	group        = "kubescape.io"
	version      = "v1"
	apiVersion   = group + "/" + version
	fieldManager = "kubescape|operator|serviceDiscoveryHandler"
)

var protocolFilter = []string{"UDP"}

var serviceListOptions = metav1.ListOptions{
	FieldSelector: "metadata.namespace!=kube-system",
}

var serviceScanSchema = schema.GroupVersionResource{
	Group:    group,
	Version:  version,
	Resource: resource,
}

func deleteServices(ctx context.Context, client dynamic.NamespaceableResourceInterface, currentServicesMetadata []metadata) {
	// get all services from the current cycle and compare them with the current CRDs

	authServices, err := client.List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.L().Ctx(ctx).Error(err.Error())
		return
	}

	for _, service := range authServices.Items {
		crdMetadata := metadata{
			name:      service.GetName(),
			namespace: service.GetNamespace(),
		}

		if !slices.Contains(currentServicesMetadata, crdMetadata) {
			err := client.Namespace(service.GetNamespace()).Delete(ctx, service.GetName(), metav1.DeleteOptions{})
			if err != nil {
				logger.L().Ctx(ctx).Error(err.Error())
			}
			logger.L().Ctx(ctx).Info("Authentication Service " + service.GetName() + " in namespace " + service.GetNamespace() + " deleted")
		}
	}
}

type serviceAuthentication struct {
	kind       string
	apiVersion string
	metadata   metadata
	spec       spec
}

type metadata struct {
	name      string
	namespace string
}

type spec struct {
	clusterIP string
	ports     []Port
}

func (sra serviceAuthentication) unstructured() (*unstructured.Unstructured, error) {
	a, err := k8sruntime.DefaultUnstructuredConverter.ToUnstructured(&sra)
	if err != nil {
		logger.L().Error(err.Error())
		return nil, err
	}
	return &unstructured.Unstructured{Object: a}, err
}

func (sra *serviceAuthentication) initialPorts(ports []v1.ServicePort) {
	sra.spec.ports = make([]Port, 0, len(ports))
	for _, port := range ports {
		sra.spec.ports = append(sra.spec.ports, Port{
			port:     int(port.Port),
			protocol: string(port.Protocol),
		})
	}
}

func (sra *serviceAuthentication) serviceScan(ctx context.Context, client dynamic.NamespaceableResourceInterface) {
	// get all ports , each port equal different address
	for idx := range sra.spec.ports {

		pr := &sra.spec.ports[idx]
		if slices.Contains(protocolFilter, string(pr.protocol)) {
			continue
		}

		//use DNS name to scan - this is the most reliable way to scan
		srvDnsName := sra.metadata.name + "." + sra.metadata.namespace
		pr.scan(ctx, srvDnsName)

	}

	serviceObj, structuredErr := sra.unstructured()
	if structuredErr != nil {
		logger.L().Ctx(ctx).Error(structuredErr.Error())
		return
	}

	_, deleteErr := client.Namespace(sra.metadata.namespace).Apply(ctx, sra.metadata.name, serviceObj, metav1.ApplyOptions{FieldManager: fieldManager})
	if deleteErr != nil {
		logger.L().Ctx(ctx).Error(deleteErr.Error())
	}
}

func serviceDiscovery(ctx context.Context, regularClient kubernetes.Interface, dynamicClient dynamic.NamespaceableResourceInterface) {
	// get a list of all  services in the cluster
	services, err := regularClient.CoreV1().Services("").List(ctx, serviceListOptions)
	if err != nil {
		logger.L().Ctx(ctx).Error(err.Error())
		return
	}

	scansWg := sync.WaitGroup{}
	antsPool, err := ants.NewPool(20)
	if err != nil {
		logger.L().Ctx(ctx).Error(err.Error())
		return
	}

	currentServiceList := make([]metadata, len(services.Items))
	for _, service := range services.Items {
		sra := serviceAuthentication{}
		sra.kind = kind
		sra.apiVersion = apiVersion
		sra.metadata.name = service.Name
		sra.metadata.namespace = service.Namespace
		sra.spec.clusterIP = service.Spec.ClusterIP
		sra.initialPorts(service.Spec.Ports)

		currentServiceList = append(currentServiceList, sra.metadata)

		scansWg.Add(1)
		antsPool.Submit(func() {
			sra.serviceScan(ctx, dynamicClient)
			scansWg.Done()
		})
	}
	scansWg.Wait()
	antsPool.Release()

	deleteServices(ctx, dynamicClient, currentServiceList)
}

func DiscoveryServiceHandler(ctx context.Context, kubeClient *k8sinterface.KubernetesApi, timeout time.Duration) {
	dynamicClient := kubeClient.DynamicClient.Resource(serviceScanSchema)
	regularClient := kubeClient.KubernetesClient

	for {
		logger.L().Ctx(ctx).Info("starting a new service discovery handling")
		serviceDiscovery(ctx, regularClient, dynamicClient)
		logger.L().Ctx(ctx).Info("finished service discovery cycle")

		time.Sleep(timeout)
	}
}
