package objectcache

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
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
