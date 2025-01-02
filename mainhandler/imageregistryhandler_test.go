package mainhandler

import (
	"context"

	"github.com/kubescape/k8s-interface/k8sinterface"
)

// func TestSetImageToTagsMap(t *testing.T) {
// 	k8sAPI := k8sinterface.NewKubernetesApi()
// 	registryScan := NewRegistryScan(k8sAPI)
// 	registryScan.registry = registry{
// 		hostname:  "quay.io",
// 		projectID: "armosec",
// 	}
// 	registryScan.registryInfo.RegistryName = "quay.io/armosec"
// 	registryScan.registryInfo.RegistryProvider = "quay.io"
// 	registryScan.registryInfo.Kind = "quay.io"
// 	registryScan.registryInfo.AuthMethod.Type = "public"
// 	registryScan.registryInfo.Include = append(registryScan.registryInfo.Exclude, "armosec/k8s-ca-webhook-ubi")

// 	repos, err := registryScan.enumerateRepos()
// 	assert.NoError(t, err)
// 	reporter := systemreports.NewBaseReport("bla", "bla", "http://localhost:7200", http.DefaultClient)
// 	reposToTags := make(chan map[string][]string, len(repos))
// 	mapUniqueRepos := make(map[string]bool, len(repos))
// 	for _, repo := range repos {
// 		if _, ok := mapUniqueRepos[repo]; ok {
// 			t.Errorf("repo %s already exists, len %d", repo, len(repos))
// 		}
// 		mapUniqueRepos[repo] = true
// 		//currentRepo := repo
// 		go registryScan.setImageToTagsMap(repo, reporter, reposToTags)
// 	}
// 	for i := 0; i < len(repos); i++ {
// 		res := <-reposToTags
// 		for k, v := range res {
// 			registryScan.mapImageToTags[k] = v
// 		}
// 	}

// }

func NewMockKubernetesAPI() *k8sinterface.KubernetesApi {
	return &k8sinterface.KubernetesApi{
		KubernetesClient: nil,
		DynamicClient:    nil,
		DiscoveryClient:  nil,
		Context:          context.Background(),
	}
}
