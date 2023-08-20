package continuousscanning

import (
	"context"
	"encoding/json"
	"io"

	"k8s.io/apimachinery/pkg/runtime/schema"
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

// MatchingRuleFetcher fetches Matching Rules from somewhere
type MatchingRuleFetcher interface {
	Fetch(ctx context.Context) (*MatchingRules, error)
}

// targetLoader loads target matching rules
type targetLoader struct {
	fetcher MatchingRuleFetcher
}

type TargetLoader interface {
	LoadGVRs(ctx context.Context) []schema.GroupVersionResource
}

// NewTargetLoader returns a new Target Loader
func NewTargetLoader(f MatchingRuleFetcher) *targetLoader {
	return &targetLoader{fetcher: f}
}

func matchRuleToGVR(apiMatch APIResourceMatch) []schema.GroupVersionResource {
	gvrs := []schema.GroupVersionResource{}

	for _, group := range apiMatch.Groups {
		for _, version := range apiMatch.Versions {
			for _, resource := range apiMatch.Resources {
				gvr := schema.GroupVersionResource{
					Group:    group,
					Version:  version,
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

type fileFetcher struct{
	r io.Reader
}

func (f *fileFetcher) Fetch(ctx context.Context) (*MatchingRules, error) {
	return parseMatchingRules(f.r)
}

// NewFileFetcher returns a new file-based rule matches fetcher
func NewFileFetcher(r io.Reader) *fileFetcher {
	return &fileFetcher{r: r}
}

// parseMatchingRules takes the data from the reader and parsess it into resource matching rules
func parseMatchingRules(r io.Reader) (*MatchingRules, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var matches *MatchingRules
	err = json.Unmarshal(data, &matches)
	return matches, err
}
