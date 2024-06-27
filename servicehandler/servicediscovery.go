package servicehandler

import (
	"context"
	"slices"
	"sync"
	"time"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape-network-scanner/cmd"
	"github.com/panjf2000/ants/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
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

var protocolFilter = []string{"UDP"}

var serviceListOptions = metav1.ListOptions{
	FieldSelector: "metadata.namespace!=kube-system",
}

var Schema = schema.GroupVersionResource{
	Group:    group,
	Version:  version,
	Resource: resource,
}

type currentServiceList [][2]string

func (sl currentServiceList) contains(name string, namespace string) bool {
	for _, service := range sl {
		if service[0] == name && service[1] == namespace {
			return true
		}
	}
	return false
}

type ServiceAuthentication struct {
	kind       string
	apiVersion string
	metadata   struct {
		name      string
		namespace string
	}
	spec struct {
		clusterIP string
		ports     []Port
	}
}

type Port struct {
	port              int
	protocol          string
	sessionLayer      string
	presentationLayer string
	applicationLayer  string
	authenticated     bool
}

func (sra ServiceAuthentication) Unstructured() (*unstructured.Unstructured, error) {
	a, err := k8sruntime.DefaultUnstructuredConverter.ToUnstructured(&sra)
	if err != nil {
		logger.L().Error(err.Error())
		return nil, err
	}
	return &unstructured.Unstructured{Object: a}, err
}

func (sra *ServiceAuthentication) initialPorts(ports []v1.ServicePort) {
	sra.spec.ports = make([]Port, 0, len(ports))
	for _, port := range ports {
		sra.spec.ports = append(sra.spec.ports, Port{
			port:     int(port.Port),
			protocol: string(port.Protocol),
		})
	}
}

func (sra *ServiceAuthentication) Discover(ctx context.Context, scansWg *sync.WaitGroup, antsPool *ants.Pool, client dynamic.NamespaceableResourceInterface) {

	for _, pr := range sra.spec.ports {
		if slices.Contains(protocolFilter, string(pr.protocol)) {
			continue
		}

		srvDnsName := sra.metadata.name + "." + sra.metadata.namespace

		scansWg.Add(1)
		antsPool.Submit(func() {
			pr.Scan(ctx, srvDnsName)
			sra.spec.ports = append(sra.spec.ports, pr)
			scansWg.Done()
		})
	}

	serviceObj, structuredErr := sra.Unstructured()
	if structuredErr != nil {
		logger.L().Ctx(ctx).Error(structuredErr.Error())
		return
	}
	_, deleteErr := client.Namespace(sra.metadata.namespace).Apply(context.TODO(), sra.metadata.name, serviceObj, metav1.ApplyOptions{FieldManager: FieldManager})

	if deleteErr != nil {
		logger.L().Ctx(ctx).Error(deleteErr.Error())
	}
}

func (port *Port) Scan(ctx context.Context, ip string) {
	result, err := cmd.ScanTargets(ctx, ip, port.port)
	port.applicationLayer = result.ApplicationLayer
	port.presentationLayer = result.PresentationLayer
	port.sessionLayer = result.SessionLayer
	port.authenticated = result.IsAuthenticated

	if result.ApplicationLayer == "" {
		port.applicationLayer = "Unknown"
		port.authenticated = true
	}

	if err != nil {
		logger.L().Ctx(ctx).Error(err.Error())
		result.ApplicationLayer = "Unknown"
		result.PresentationLayer = "Unknown"
		result.SessionLayer = "Unknown"
		result.IsAuthenticated = true
	}
}

func (csl currentServiceList) deleteServices(ctx context.Context, client dynamic.NamespaceableResourceInterface) error {
	authServices, err := client.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, service := range authServices.Items {
		if !csl.contains(service.GetName(), service.GetNamespace()) {
			err := client.Namespace(service.GetNamespace()).Delete(context.TODO(), service.GetName(), metav1.DeleteOptions{})
			if err != nil {
				logger.L().Error(err.Error())
				continue
			}
			logger.L().Ctx(ctx).Info("Authentication Service " + service.GetName() + " in namespace " + service.GetNamespace() + " deleted")
		}
	}
	return err
}

func DiscoveryServiceHandler(ctx context.Context, kubeClient *k8sinterface.KubernetesApi, timeout time.Duration) {
	{
		dynamicClient := kubeClient.DynamicClient.Resource(Schema)
		regularClient := kubeClient.KubernetesClient.CoreV1()

		for {
			logger.L().Ctx(ctx).Info("starting a new service discovery handling")
			currentServiceList := make(currentServiceList, 0)

			// get a list of all  services in the cluster
			services, err := regularClient.Services("").List(context.TODO(), serviceListOptions)
			if err != nil {
				logger.L().Ctx(ctx).Error(err.Error())
				return
			}

			scansWg := sync.WaitGroup{}
			antsPool, _ := ants.NewPool(20)

			for _, service := range services.Items {
				sra := ServiceAuthentication{}
				sra.kind = kind
				sra.apiVersion = apiVersion
				sra.metadata.name = service.Name
				sra.metadata.namespace = service.Namespace
				sra.spec.clusterIP = service.Spec.ClusterIP
				sra.initialPorts(service.Spec.Ports)

				currentServiceList = append(currentServiceList, [2]string{service.Name, service.Namespace})
				sra.Discover(ctx, &scansWg, antsPool, dynamicClient)
			}
			scansWg.Wait()
			antsPool.Release()

			currentServiceList.deleteServices(ctx, dynamicClient)
			logger.L().Ctx(ctx).Info("finished service discovery cycle")

			time.Sleep(timeout)
		}
	}
}
