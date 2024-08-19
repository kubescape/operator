
package objectcache

type ObjectCache interface {
	GetKubernetesCache() KubernetesCache
}

type ObjectCacheImpl struct {
	kubernetesCache KubernetesCache
}

func (oc ObjectCacheImpl) GetKubernetesCache() KubernetesCache {
	return oc.kubernetesCache
}

func NewObjectCache(kubernetesCache KubernetesCache) *ObjectCacheImpl {
	return &ObjectCacheImpl{
		kubernetesCache: kubernetesCache,
	}
}
