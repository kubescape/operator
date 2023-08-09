package continuousscanning

import (
	"context"
	"encoding/json"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
)

const (
	defaultConfigMapName  = "kubescape-config"
	defaultTargetsKeyName = "matches.json"
)

// APIResourceMatch is a definition of a matching rule for API Resources
//
// It defines a rule on how to generate GVRs from it. The rule definition
// captures ANY of the mentioned Groups, Versions and Resources
type APIResourceMatch struct {
	Groups    []string `json:"apiGroups"`
	Versions  []string `json:"apiVersions"`
	Resources []string `json:"resources"`
}

// MatchingRules is a definition of resource matching rules
type MatchingRules struct {
	APIResources []APIResourceMatch `json:"match"`
	Namespaces   []string           `json:"namespaces"`
}

// configMapFetcher fetches Matching Rules from a ConfigMap
type configMapFetcher struct {
	client          kubernetes.Interface
	configMapName   string
	matchesFilename string
}

func NewConfigMapTargetFetcher(k8sclient kubernetes.Interface) *configMapFetcher {
	return &configMapFetcher{
		client:          k8sclient,
		configMapName:   defaultConfigMapName,
		matchesFilename: defaultTargetsKeyName,
	}
}

func (l *configMapFetcher) Fetch(ctx context.Context) (MatchingRules, error) {
	cm, err := l.client.CoreV1().ConfigMaps("kubescape").Get(ctx, l.configMapName, v1.GetOptions{})
	if err != nil {
		return MatchingRules{}, err
	}

	data := cm.BinaryData[l.matchesFilename]

	var matches MatchingRules
	err = json.Unmarshal(data, &matches)
	if err != nil {
		return matches, err
	}

	return matches, nil
}

// Fetcher fetches Matching Rules from some somewhere
type Fetcher interface {
	Fetch(ctx context.Context) (MatchingRules, error)
}

// targetLoader loads target matching rules
type targetLoader struct {
	fetcher Fetcher
}

// NewTargetLoader returns a new Target Loader
func NewTargetLoader(f Fetcher) *targetLoader {
	return &targetLoader{fetcher: f}
}

func matchRuleToGVR(apiMatch APIResourceMatch) []schema.GroupVersionResource {
	gvrs := []schema.GroupVersionResource{}

	for _, group := range apiMatch.Groups {
		for _, version := range apiMatch.Versions {
			for _, resource := range apiMatch.Resources {
				gvr := schema.GroupVersionResource{
					Group: group,
					Version: version,
					Resource: resource,
				}
				gvrs = append(gvrs, gvr)
			}
		}
	}
	return gvrs
}

// LoadGVRs loads GroupVersionResource definitions
func (l *targetLoader) LoadGVRs(ctx context.Context) []schema.GroupVersionResource {
	gvrs := []schema.GroupVersionResource{}

	rules, _ := l.fetcher.Fetch(ctx)

	apiResourceMatches := rules.APIResources
	for idx := range apiResourceMatches {
		ruleGvrs := matchRuleToGVR(apiResourceMatches[idx])
		gvrs = append(gvrs, ruleGvrs...)
	}

	return gvrs
}
