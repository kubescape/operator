package servicehandler

import (
	"context"
	"fmt"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/panjf2000/ants/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/pager"
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

var protocolFilter = mapset.NewSet("UDP")

var serviceListOptions = metav1.ListOptions{
	FieldSelector: "metadata.namespace!=kube-system",
}

var ServiceScanSchema = schema.GroupVersionResource{
	Group:    group,
	Version:  version,
	Resource: resource,
}

func deleteServices(ctx context.Context, client dynamic.NamespaceableResourceInterface, currentServices mapset.Set[string]) {
	// get all services from the current cycle and compare them with the current CRDs

	if err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (k8sruntime.Object, error) {
		return client.List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj k8sruntime.Object) error {
		service := obj.(*unstructured.Unstructured)
		if !currentServices.Contains(service.GetNamespace() + "/" + service.GetName()) {
			err := client.Namespace(service.GetNamespace()).Delete(ctx, service.GetName(), metav1.DeleteOptions{})
			if err != nil {
				logger.L().Ctx(ctx).Error("failed to delete service", helpers.Error(err), helpers.String("namespace", service.GetNamespace()), helpers.String("name", service.GetName()))
			} else {
				logger.L().Debug("Authentication Service " + service.GetName() + " in namespace " + service.GetNamespace() + " deleted")
			}
		}
		return nil
	}); err != nil {
		logger.L().Ctx(ctx).Error(err.Error())
		return
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

func (sra *serviceAuthentication) unstructured() (*unstructured.Unstructured, error) {
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
		if protocolFilter.Contains(pr.protocol) {
			continue
		}

		//use DNS name to scan - this is the most reliable way to scan
		srvDnsName := sra.metadata.name + "." + sra.metadata.namespace
		//FIXME: application scan can return different applicationLayer result at different scans
		pr.scan(ctx, srvDnsName)
	}

	return sra.applyCrd(ctx, client)
}

func discoveryService(ctx context.Context, regularClient kubernetes.Interface, dynamicClient dynamic.Interface) error {
	scanWg := sync.WaitGroup{}
	p, err := ants.NewPoolWithFunc(workerNum, func(i interface{}) {
		defer scanWg.Done()
		sra, ok := i.(serviceAuthentication)
		if !ok {
			return
		}
		scanErr := sra.serviceScan(ctx, dynamicClient.Resource(ServiceScanSchema))
		if scanErr != nil {
			logger.L().Ctx(ctx).Error("failed to scan service", helpers.Error(scanErr), helpers.String("namespace", sra.metadata.namespace), helpers.String("name", sra.metadata.name))
		}
	})
	if err != nil {
		return fmt.Errorf("failed to create a pool of workers: %w", err)
	}

	currentServices := mapset.NewSet[string]()
	_ = pager.New(func(ctx context.Context, opts metav1.ListOptions) (k8sruntime.Object, error) {
		return regularClient.CoreV1().Services("").List(ctx, opts)
	}).EachListItem(ctx, serviceListOptions, func(obj k8sruntime.Object) error {
		scanWg.Add(1)
		service := obj.(*corev1.Service)
		sra := serviceAuthentication{}
		sra.kind = kind
		sra.apiVersion = apiVersion
		sra.metadata.name = service.Name
		sra.metadata.namespace = service.Namespace
		sra.spec.clusterIP = service.Spec.ClusterIP
		sra.spec.ports = K8sPortsTranslator(service.Spec.Ports)
		currentServices.Add(service.Namespace + "/" + service.Name)
		err := p.Invoke(sra)
		if err != nil {
			logger.L().Ctx(ctx).Error(err.Error())
		}
		return nil
	})
	scanWg.Wait()
	p.Release()

	deleteServices(ctx, dynamicClient.Resource(ServiceScanSchema), currentServices)
	return nil
}

func DiscoveryServiceHandler(ctx context.Context, kubeClient *k8sinterface.KubernetesApi, interval time.Duration) {
	dynamicClient := kubeClient.DynamicClient
	regularClient := kubeClient.KubernetesClient

	for {
		logger.L().Info("starting a new service discovery handling")
		err := discoveryService(ctx, regularClient, dynamicClient)
		if err != nil {
			logger.L().Ctx(ctx).Error(err.Error())
		} else {
			logger.L().Info("finished service discovery cycle")
		}
		time.Sleep(interval)

	}
}
