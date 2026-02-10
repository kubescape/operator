package objectcache

import (
	"context"

	"github.com/kubescape/k8s-interface/k8sinterface"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type KubernetesCacheMockImpl struct{}

func (om KubernetesCacheMockImpl) GetClientset() kubernetes.Interface {
	client := k8sinterface.NewKubernetesApiMock().KubernetesClient
	initializeClient(client)

	return client
}

func initializeClient(client kubernetes.Interface) {
	pod := &corev1.Pod{
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
		Spec: corev1.PodSpec{
			NodeName: "test-node",
			Containers: []corev1.Container{
				{
					Name:  "test-container",
					Image: "nginx:1.14.2",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "192.168.1.1",
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "test-container",
					ContainerID: "containerd://abcdef1234567890",
					Image:       "nginx:1.14.2",
					ImageID:     "docker-pullable://nginx@sha256:abc123def456",
				},
			},
		},
	}

	client.CoreV1().Pods("test-namespace").Create(context.TODO(), pod, metav1.CreateOptions{})
}
