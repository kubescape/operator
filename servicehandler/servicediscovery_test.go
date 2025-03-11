package servicehandler

import (
	"context"
	"slices"
	"testing"

	"github.com/kubescape/go-logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicFake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	kubernetesFake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

var TestAuthentications = serviceAuthentication{
	kind:       "ServiceScanResult",
	apiVersion: "servicesscanresults",
	metadata: metadata{
		name:      "test",
		namespace: "test",
	},
	spec: spec{
		clusterIP: "test",
		ports: []Port{
			{
				port:              80,
				protocol:          "TCP",
				applicationLayer:  "sql",
				authenticated:     ptr.To(true),
				sessionLayer:      "tcp",
				presentationLayer: "http",
			},
			{
				port:              443,
				protocol:          "TCP",
				applicationLayer:  "kafka",
				authenticated:     ptr.To(true),
				sessionLayer:      "tcp",
				presentationLayer: "http",
			},
		},
	},
}

func Test_translate(t *testing.T) {
	tests := []struct {
		name  string
		ports []corev1.ServicePort
		want  []Port
	}{
		{
			name:  "empty",
			ports: []corev1.ServicePort{},
			want:  []Port{},
		},
		{
			name: "one port",
			ports: []corev1.ServicePort{
				{
					Port:     80,
					Protocol: "TCP",
				},
			},
			want: []Port{
				{
					port:     80,
					protocol: "TCP",
				},
			},
		},
		{
			name: "two ports",
			ports: []corev1.ServicePort{
				{
					Port:     80,
					Protocol: "TCP",
				},
				{
					Port:     443,
					Protocol: "TCP",
				},
			},
			want: []Port{
				{
					port:     80,
					protocol: "TCP",
				},
				{
					port:     443,
					protocol: "TCP",
				},
			},
		},

		// add several ports
		// add duplicate ports (not sure if it's your use case?)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := K8sPortsTranslator(tt.ports)
			for i := range tt.want {
				assert.Equal(t, tt.want[i], got[i], "Elements at index %d are not equal", i)
			}
		})
	}
}

func TestDiscoveryServiceHandler(t *testing.T) {
	//write a component test that creates fake client and test the service discovery and see if it creates a crd
	//and if it deletes the crd
	//IMPORTANT: fake client doesn't have an Apply option like the real client so we need to create the crd and check if it exists -it will blog errors but will pass
	testCases := []struct {
		name     string
		services []runtime.Object
		want     []unstructured.Unstructured
		delete   []runtime.Object
	}{
		{
			name: "existing_services_found",
			services: []runtime.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service1",
						Namespace: "test1",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Port:     80,
								Protocol: "TCP",
							},
							{
								Port:     443,
								Protocol: "UDP",
							},
						},
					},
				},

				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service2",
						Namespace: "test2",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Port:     80,
								Protocol: "TCP",
							},
							{
								Port:     443,
								Protocol: "UDP",
							},
						},
					},
				},
			},
			want: []unstructured.Unstructured{
				{Object: map[string]interface{}{"apiVersion": "kubescape.io/v1", "kind": "ServiceScanResult",
					"metadata": map[string]interface{}{"name": "service1", "namespace": "test1"},
					"spec": map[string]interface{}{"clusterIP": "",
						"ports": []interface{}{
							map[string]interface{}{"applicationLayer": "", "authenticated": nil, "port": int64(80), "presentationLayer": "", "protocol": "TCP", "sessionLayer": ""},
							map[string]interface{}{"applicationLayer": "", "authenticated": nil, "port": int64(443), "presentationLayer": "", "protocol": "UDP", "sessionLayer": ""},
						}}}},
				{Object: map[string]interface{}{"apiVersion": "kubescape.io/v1", "kind": "ServiceScanResult",
					"metadata": map[string]interface{}{"name": "service2", "namespace": "test2"},
					"spec": map[string]interface{}{"clusterIP": "",
						"ports": []interface{}{
							map[string]interface{}{"applicationLayer": "", "authenticated": nil, "port": int64(80), "presentationLayer": "", "protocol": "TCP", "sessionLayer": ""},
							map[string]interface{}{"applicationLayer": "", "authenticated": nil, "port": int64(443), "presentationLayer": "", "protocol": "UDP", "sessionLayer": ""},
						}}}},
			},
		},
		{
			name:     "no_services",
			services: []runtime.Object{},
			want:     nil,
		},
		{
			name: "existing_service_missing_port",
			services: []runtime.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service1",
						Namespace: "test1",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Port:     80,
								Protocol: "TCP",
							},
							{
								Port:     443,
								Protocol: "UDP",
							},
						},
					},
				},
			},
			want: []unstructured.Unstructured{
				{Object: map[string]interface{}{"apiVersion": "kubescape.io/v1", "kind": "ServiceScanResult",
					"metadata": map[string]interface{}{"name": "service1", "namespace": "test1"},
					"spec": map[string]interface{}{"clusterIP": "",
						"ports": []interface{}{
							map[string]interface{}{"applicationLayer": "", "authenticated": nil, "port": int64(80), "presentationLayer": "", "protocol": "TCP", "sessionLayer": ""},
							map[string]interface{}{"applicationLayer": "", "authenticated": nil, "port": int64(443), "presentationLayer": "", "protocol": "UDP", "sessionLayer": ""},
						}}}},
			},
		},
		{
			name: "headless_service",
			services: []runtime.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service1",
						Namespace: "test1",
						Labels: map[string]string{
							"label1": "value1",
						},
					},
					Spec: corev1.ServiceSpec{
						ClusterIP: "None",
						Ports:     []corev1.ServicePort{},
					},
				},
			},
			want: []unstructured.Unstructured{
				{Object: map[string]interface{}{"apiVersion": "kubescape.io/v1", "kind": "ServiceScanResult",
					"metadata": map[string]interface{}{"name": "service1", "namespace": "test1"},
					"spec": map[string]interface{}{"clusterIP": "None",
						"ports": []interface{}{},
					}}},
			},
		},
		{
			name: "delete_service",
			services: []runtime.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service1",
						Namespace: "test1",
						Labels: map[string]string{
							"label1": "value1",
						},
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Port:     80,
								Protocol: "TCP",
							},
						},
					},
				},
			},
			want: []unstructured.Unstructured{
				{Object: map[string]interface{}{"apiVersion": "kubescape.io/v1", "kind": "ServiceScanResult",
					"metadata": map[string]interface{}{"name": "service1", "namespace": "test1"},
					"spec":     map[string]interface{}{"clusterIP": "", "ports": []interface{}{map[string]interface{}{"applicationLayer": "", "authenticated": nil, "port": int64(80), "presentationLayer": "", "protocol": "TCP", "sessionLayer": ""}}}}},
			},
			delete: []runtime.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "deleteService",
						Namespace: "delete",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Port:     80,
								Protocol: "TCP",
							},
							{
								Port:     443,
								Protocol: "UDP",
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger.InitDefaultLogger()
			ctx := context.Background()
			testSchema := runtime.NewScheme()
			dynamicClient := dynamicFake.NewSimpleDynamicClientWithCustomListKinds(testSchema, map[schema.GroupVersionResource]string{
				ServiceScanSchema: "ServiceScanList",
			},
			)
			inObjects := slices.Concat(tc.services, tc.delete)
			regClient := kubernetesFake.NewSimpleClientset(inObjects...)

			var crds *unstructured.UnstructuredList
			for i := 0; i < 10; i++ {
				services, _ := serviceExtractor(ctx, regClient)
				for _, service := range services {
					obj, _ := service.unstructured()
					_, err := dynamicClient.Resource(ServiceScanSchema).Namespace(service.metadata.namespace).Create(ctx, obj, metav1.CreateOptions{})
					if !errors.IsAlreadyExists(err) {
						require.NoError(t, err)
					}

				}

				err := discoveryService(context.Background(), regClient, dynamicClient)
				assert.NoError(t, err)

				crds, _ = dynamicClient.Resource(ServiceScanSchema).List(ctx, metav1.ListOptions{})
				if tc.delete != nil {
					for _, delService := range tc.delete {
						err = regClient.CoreV1().Services(delService.(*corev1.Service).Namespace).Delete(ctx, delService.(*corev1.Service).Name, metav1.DeleteOptions{})
						require.NoError(t, err)
						tc.delete = nil
					}
				}
			}

			assert.Equal(t, tc.want, crds.Items, "CRDs mismatch")
		})

	}

}

func getClusterServices(ctx context.Context, regularClient kubernetes.Interface) (*corev1.ServiceList, error) {
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
