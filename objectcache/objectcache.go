package objectcache

type ObjectCache interface {
	GetKubernetesCache() KubernetesCache
}
