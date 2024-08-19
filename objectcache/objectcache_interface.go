package objectcache

type ObjectCacheImpl struct {
	kubernetesCache KubernetesCache
}

func NewObjectCache(kubernetesCache KubernetesCache) *ObjectCacheImpl {
	return &ObjectCacheImpl{
		kubernetesCache: kubernetesCache,
	}
}

func (oc ObjectCacheImpl) GetKubernetesCache() KubernetesCache {
	return oc.kubernetesCache
}
