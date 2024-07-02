package servicehandler

import (
	"context"
	"slices"
	"testing"

	"gotest.tools/v3/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicFake "k8s.io/client-go/dynamic/fake"
	kubernetesFake "k8s.io/client-go/kubernetes/fake"
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
				authenticated:     true,
				sessionLayer:      "tcp",
				presentationLayer: "http",
			},
			{
				port:              443,
				protocol:          "TCP",
				applicationLayer:  "kafka",
				authenticated:     true,
				sessionLayer:      "tcp",
				presentationLayer: "http",
			},
		},
	},
}

func Test_translate(t *testing.T) {
	tests := []struct {
		name  string
		ports []v1.ServicePort
		want  []Port
	}{
		{
			name:  "empty",
			ports: []v1.ServicePort{},
			want:  []Port{},
		},
		{
			name: "one port",
			ports: []v1.ServicePort{
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
			ports: []v1.ServicePort{
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
	testCases := []struct {
		name     string
		services []runtime.Object
		want     []metadata
	}{
		{
			name: "existing_services_found",
			services: []runtime.Object{
				&v1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service1",
						Namespace: "test1",
					},
					Spec: v1.ServiceSpec{
						Ports: []v1.ServicePort{
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

				&v1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service2",
						Namespace: "test2",
					},
					Spec: v1.ServiceSpec{
						Ports: []v1.ServicePort{
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
			want: []metadata{
				{
					name:      "service1",
					namespace: "test1",
				},
				{
					name:      "service2",
					namespace: "test2",
				},
			},
		},
		{
			name:     "no_services",
			services: []runtime.Object{},
			want:     []metadata{},
		},
		{
			name: "existing_service_missing_port",
			services: []runtime.Object{
				&v1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service1",
						Namespace: "test1",
					},
					Spec: v1.ServiceSpec{
						Ports: []v1.ServicePort{
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
			want: []metadata{
				{
					name:      "service1",
					namespace: "test1",
				},
			},
		},
		{
			name: "headless_service",
			services: []runtime.Object{
				&v1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service1",
						Namespace: "test1",
						Labels: map[string]string{
							"label1": "value1",
						},
					},
					Spec: v1.ServiceSpec{
						ClusterIP: "None",
						Ports:     []v1.ServicePort{},
					},
				},
			},
			want: []metadata{
				{
					name:      "service1",
					namespace: "test1",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			testSchema := runtime.NewScheme()
			dynamicClient := dynamicFake.NewSimpleDynamicClientWithCustomListKinds(testSchema, map[schema.GroupVersionResource]string{
				ServiceScanSchema: "ServiceScanList",
			},
			)

			services, _ := serviceExtractor(ctx, kubernetesFake.NewSimpleClientset(tc.services...))
			for _, service := range services {
				obj, _ := service.unstructured()
				dynamicClient.Resource(ServiceScanSchema).Namespace(service.metadata.namespace).Create(ctx, obj, metav1.CreateOptions{})
			}
			discoveryService(context.Background(), kubernetesFake.NewSimpleClientset(tc.services...), dynamicClient)

			crds, _ := dynamicClient.Resource(ServiceScanSchema).List(ctx, metav1.ListOptions{})

			for _, crd := range crds.Items {
				crdMetadata := metadata{
					name:      crd.GetName(),
					namespace: crd.GetNamespace(),
				}
				t.Log(crdMetadata)
				if !slices.Contains(tc.want, crdMetadata) {
					t.Errorf("unexpected CRD %v", crd)
				}
			}
		})
	}

}
