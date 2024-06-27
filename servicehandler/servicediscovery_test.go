package servicehandler

import (
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var TestAuthentications = ServiceAuthentication{
	kind:       "ServiceScanResult",
	apiVersion: "servicesscanresults",
	metadata: struct {
		name      string
		namespace string
	}{
		name:      "test",
		namespace: "test",
	},
	spec: struct {
		clusterIP string
		ports     []Port
	}{
		clusterIP: "127.0.0.1",
		ports: []Port{
			{
				port:              80,
				protocol:          "TCP",
				sessionLayer:      "test",
				presentationLayer: "test",
				applicationLayer:  "test",
				authenticated:     true,
			},
			{
				port:              443,
				protocol:          "TCP",
				sessionLayer:      "test",
				presentationLayer: "test",
				applicationLayer:  "test",
				authenticated:     true,
			},
		},
	},
}

func TestUnstructured(t *testing.T) {
	unstructuredObject, err := TestAuthentications.Unstructured()
	if err != nil {
		t.Errorf("Unstructured() got an error: %v", err)
	}
	objType := reflect.TypeOf(unstructuredObject)
	if unstructuredType := reflect.TypeOf(&unstructured.Unstructured{}); objType != unstructuredType {
		t.Errorf("Unstructured() returned an object of unexpected type")
	}
	if unstructuredObject.Object == nil {
		t.Errorf("Unstructured() returned an object with nil value")
	}
}

func TestContains(t *testing.T) {
	services := currentServiceList{
		{"test", "test"},
	}
	if !services.contains("test", "test") {
		t.Errorf("contains() returned false")
	}
}

func TestInitialPorts(t *testing.T) {
	ports := []v1.ServicePort{
		{
			Port:     80,
			Protocol: "TCP",
		},
		{
			Port:     443,
			Protocol: "TCP",
		},
	}
	TestAuthentications.initialPorts(ports)
	if len(TestAuthentications.spec.ports) != 2 {
		t.Errorf("initialPorts() did not add all ports")
	}
}

// func TestDiscoveryServiceHandler(t *testing.T) {

// 	ctx := context.Background()

// 	kubeconfig := os.Getenv("HOME") + "/.kube/config" // Adjust path as necessary

// 	// Build kubeconfig from file
// 	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
// 	if err != nil {
// 		panic(err.Error())
// 	}

// 	// Create Kubernetes clientset
// 	clientset, err := kubernetes.NewForConfig(config)
// 	if err != nil {
// 		panic(err.Error())
// 	}

// 	kubeClient := clientset.CoreV1()
// 	dynamicClient, _ := dynamic.NewForConfig(config)
// 	dynamicClient1 := dynamicClient.Resource(Schema)
// 	logger.L().Ctx(ctx).Info(kubeconfig)

// 	logger.L().Ctx(ctx).Info("starting a new service discovery handling")
// 	currentServiceList := make(currentServiceList, 0)

// 	// get a list of all  services in the cluster
// 	services, err := kubeClient.Services("").List(context.TODO(), serviceListOptions)
// 	t.Log(services, err)
// 	if err != nil {
// 		logger.L().Ctx(ctx).Error(err.Error())
// 		return
// 	}

// 	scansWg := sync.WaitGroup{}
// 	antsPool, _ := ants.NewPool(20)

// 	for _, service := range services.Items {
// 		logger.L().Ctx(ctx).Info(fmt.Sprint(service.Name, service.Namespace))
// 		sra := ServiceAuthentication{}
// 		sra.kind = kind
// 		sra.apiVersion = apiVersion
// 		sra.metadata.name = service.Name
// 		sra.metadata.namespace = service.Namespace
// 		sra.spec.clusterIP = service.Spec.ClusterIP
// 		sra.initialPorts(service.Spec.Ports)

// 		currentServiceList = append(currentServiceList, [2]string{service.Name, service.Namespace})
// 		sra.Discover(ctx, &scansWg, antsPool, dynamicClient1)
// 	}
// 	scansWg.Wait()
// 	antsPool.Release()

// 	currentServiceList.deleteServices(ctx, dynamicClient1)
// 	logger.L().Ctx(ctx).Info("finished service discovery cycle")
// }

//TODO: Add more tests

//TODO use fake client

//TODO add tests to strict functionallity

//TODO use kwok for perfomnace by using scale
