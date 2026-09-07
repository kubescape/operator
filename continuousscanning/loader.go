package continuousscanning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/runtime/schema"
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

// TargetLoader loads matching-rule targets used to establish watches.
type TargetLoader interface {
	// Load returns the GVRs to watch and the namespaces to restrict them to.
	// An empty namespaces slice means every namespace.
	Load(ctx context.Context) ([]schema.GroupVersionResource, []string, error)
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

// Load fetches matching rules once and returns the GVRs and namespaces to watch.
func (l *targetLoader) Load(ctx context.Context) ([]schema.GroupVersionResource, []string, error) {
	rules, err := l.fetcher.Fetch(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch matching rules: %w", err)
	}
	if rules == nil {
		return nil, nil, errors.New("matching rules are null")
	}

	gvrs := []schema.GroupVersionResource{}
	for idx := range rules.APIResources {
		gvrs = append(gvrs, matchRuleToGVR(rules.APIResources[idx])...)
	}

	return gvrs, rules.Namespaces, nil
}

type fileFetcher struct {
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

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("matching rules are empty")
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return nil, errors.New("matching rules are null")
	}

	var matches MatchingRules
	if err := json.Unmarshal(trimmed, &matches); err != nil {
		return nil, fmt.Errorf("failed to parse matching rules: %w", err)
	}
	return &matches, nil
}
