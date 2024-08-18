package objectcache

import (
	"context"

	"github.com/kubescape/k8s-interface/k8sinterface"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type KubernetesCache interface {
	GetClientset() kubernetes.Interface
}

type KubernetesCacheImpl struct {
	kubernetesClient *k8sinterface.KubernetesApi
}

func (kc KubernetesCacheImpl) GetClientset() kubernetes.Interface {
	return kc.kubernetesClient.KubernetesClient
}

func NewKubernetesCache(kubernetesClient *k8sinterface.KubernetesApi) *KubernetesCacheImpl {
	return &KubernetesCacheImpl{
		kubernetesClient: kubernetesClient,
	}
}

//Mock implementation of KubernetesCache
type KubernetesCacheMockImpl struct{}

func (om KubernetesCacheMockImpl) GetClientset() kubernetes.Interface {
	client := k8sinterface.NewKubernetesApiMock().KubernetesClient
	initializeClient(client)

	return client
}

func initializeClient(client kubernetes.Interface) {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "test-namespace",
			Labels: map[string]string{
				"app":        "test-app",
				"workload":   "test-workload",
				"controller": "ReplicaSet",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "ReplicaSet",
					Name: "test-workload",
				},
			},
		},
		Spec: v1.PodSpec{
			NodeName: "test-node",
			Containers: []v1.Container{
				{
					Name:  "test-container",
					Image: "nginx:1.14.2",
				},
			},
		},
		Status: v1.PodStatus{
			Phase: v1.PodRunning,
			PodIP: "192.168.1.1",
		},
	}

	client.CoreV1().Pods("test-namespace").Create(context.TODO(), pod, metav1.CreateOptions{})
}
