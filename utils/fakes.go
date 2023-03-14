package utils

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
	k8s "k8s.io/client-go/kubernetes"
)


// NewK8sInterfaceFake returns a new K8sInterface with a fake Kubernetes Client attached
//
// This function is a Dependency Injection-friendly version for the
// `KubernetesApi` constructor that allows to inject any Kubernetes Clients.
// For example, the official fake Kubernetes client, so unit tests would have a
// suitable test double instead of trying to talk to a real cluster
func NewK8sInterfaceFake(k8sClient k8s.Interface) *k8sinterface.KubernetesApi {
	return &k8sinterface.KubernetesApi{KubernetesClient: k8sClient}
}
