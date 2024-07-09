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
	workerNum    = int(20)
)

var protocolFilter = []string{"UDP"}

var serviceListOptions = metav1.ListOptions{
	FieldSelector: "metadata.namespace!=kube-system",
}

var ServiceScanSchema = schema.GroupVersionResource{
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
				continue
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

func (sra *serviceAuthentication) applyCrd(ctx context.Context, client dynamic.NamespaceableResourceInterface) error {
	serviceObj, structuredErr := sra.unstructured()
	if structuredErr != nil {
		logger.L().Ctx(ctx).Error(structuredErr.Error())
		return nil
	}

	_, applyErr := client.Namespace(sra.metadata.namespace).Apply(ctx, sra.metadata.name, serviceObj, metav1.ApplyOptions{FieldManager: fieldManager})
	if applyErr != nil {
		return applyErr
	}
	return nil
}

func (sra *serviceAuthentication) serviceScan(ctx context.Context, client dynamic.NamespaceableResourceInterface) error {
	// get all ports , each port equal different address
	for idx := range sra.spec.ports {

		pr := &sra.spec.ports[idx]
		if slices.Contains(protocolFilter, string(pr.protocol)) {
			continue
		}

		//use DNS name to scan - this is the most reliable way to scan
		srvDnsName := sra.metadata.name + "." + sra.metadata.namespace
		//FIXME: application scan can return different applicationLayer result at different scans
		pr.scan(ctx, srvDnsName)
	}

	return sra.applyCrd(ctx, client)
}

func getClusterServices(ctx context.Context, regularClient kubernetes.Interface) (*v1.ServiceList, error) {
	services, err := regularClient.CoreV1().Services("").List(ctx, serviceListOptions)
	if err != nil {
		logger.L().Ctx(ctx).Error(err.Error())
		return nil, err
	}
	return services, nil
}

func serviceExtractor(ctx context.Context, regularClient kubernetes.Interface) ([]serviceAuthentication, []metadata) {
	// get a list of all  services in the cluster
	services, err := getClusterServices(ctx, regularClient)
	if err != nil {
		return []serviceAuthentication{}, []metadata{}
	}

	currentServiceList := make([]serviceAuthentication, 0, len(services.Items))
	metadataList := make([]metadata, 0, len(services.Items))
	for _, service := range services.Items {
		sra := serviceAuthentication{}
		sra.kind = kind
		sra.apiVersion = apiVersion
		sra.metadata.name = service.Name
		sra.metadata.namespace = service.Namespace
		sra.spec.clusterIP = service.Spec.ClusterIP
		sra.spec.ports = K8sPortsTranslator(service.Spec.Ports)

		currentServiceList = append(currentServiceList, sra)
		metadataList = append(metadataList, sra.metadata)
	}
	return currentServiceList, metadataList

}

func discoveryService(ctx context.Context, regularClient kubernetes.Interface, dynamicClient dynamic.Interface) error {
	serviceList, metadataList := serviceExtractor(ctx, regularClient)

	scanWg := sync.WaitGroup{}
	p, err := ants.NewPoolWithFunc(workerNum, func(i interface{}) {
		defer scanWg.Done()
		sra, ok := i.(serviceAuthentication)
		if !ok {
			return
		}
		scanErr := sra.serviceScan(ctx, dynamicClient.Resource(ServiceScanSchema))
		if scanErr != nil {
			logger.L().Ctx(ctx).Error(scanErr.Error())
		}
	})

	if err != nil {
		return err
	}

	for _, sra := range serviceList {
		scanWg.Add(1)
		err := p.Invoke(sra)
		if err != nil {
			logger.L().Ctx(ctx).Error(err.Error())
			continue
		}
	}
	scanWg.Wait()
	p.Release()

	deleteServices(ctx, dynamicClient.Resource(ServiceScanSchema), metadataList)
	return nil
}

func DiscoveryServiceHandler(ctx context.Context, kubeClient *k8sinterface.KubernetesApi, interval time.Duration) {
	dynamicClient := kubeClient.DynamicClient
	regularClient := kubeClient.KubernetesClient

	for {
		logger.L().Ctx(ctx).Info("starting a new service discovery handling")
		err := discoveryService(ctx, regularClient, dynamicClient)
		if err != nil {
			logger.L().Ctx(ctx).Error(err.Error())
		} else {
			logger.L().Ctx(ctx).Info("finished service discovery cycle")
		}
		time.Sleep(interval)

	}
}
