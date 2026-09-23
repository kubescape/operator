package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

// namespaceFilter is immutable after publication. Readers use a single snapshot
// so inclusion precedence and compiled patterns always belong to the same update.
type namespaceFilter struct {
	include, exclude                 []string
	includePatterns, excludePatterns []string
	includeRegex, excludeRegex       []*regexp.Regexp
}

func newNamespaceFilter(c Config) (*namespaceFilter, error) {
	inc, err := compileRegexes(c.IncludeNamespacesRegex)
	if err != nil {
		return nil, fmt.Errorf("invalid includeNamespacesRegex: %w", err)
	}
	exc, err := compileRegexes(c.ExcludeNamespacesRegex)
	if err != nil {
		return nil, fmt.Errorf("invalid excludeNamespacesRegex: %w", err)
	}
	return &namespaceFilter{
		include: slices.Clone(c.IncludeNamespaces), exclude: slices.Clone(c.ExcludeNamespaces),
		includePatterns: slices.Clone(c.IncludeNamespacesRegex), excludePatterns: slices.Clone(c.ExcludeNamespacesRegex),
		includeRegex: inc, excludeRegex: exc,
	}, nil
}

// namespaceList accepts the same string/array forms as startup configuration,
// without weakly converting numbers, booleans or null into namespace names.
type namespaceList []string

func (l *namespaceList) UnmarshalJSON(data []byte) error {
	var value interface{}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	switch v := value.(type) {
	case string:
		if v == "" {
			*l = namespaceList{}
		} else {
			*l = strings.Split(v, ",")
		}
	case []interface{}:
		*l = make(namespaceList, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return fmt.Errorf("namespace list entries must be strings")
			}
			*l = append(*l, s)
		}
	default:
		return fmt.Errorf("namespace list must be a string or an array of strings")
	}
	return nil
}

// UpdateNamespaceFilters validates a complete document before atomically replacing
// the active filters. It returns whether the filter content changed.
func (c *OperatorConfig) UpdateNamespaceFilters(data []byte) (bool, error) {
	var doc struct {
		Include      namespaceList `json:"includeNamespaces"`
		Exclude      namespaceList `json:"excludeNamespaces"`
		IncludeRegex namespaceList `json:"includeNamespacesRegex"`
		ExcludeRegex namespaceList `json:"excludeNamespacesRegex"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&doc); err != nil {
		return false, fmt.Errorf("invalid namespace filters: %w", err)
	}
	if err := d.Decode(new(interface{})); err != io.EOF {
		return false, fmt.Errorf("namespace filters must contain exactly one JSON document")
	}
	if doc.Include == nil || doc.Exclude == nil {
		return false, fmt.Errorf("includeNamespaces and excludeNamespaces are required")
	}
	next, err := newNamespaceFilter(Config{
		IncludeNamespaces: doc.Include, ExcludeNamespaces: doc.Exclude,
		IncludeNamespacesRegex: doc.IncludeRegex, ExcludeNamespacesRegex: doc.ExcludeRegex,
	})
	if err != nil {
		return false, err
	}
	previous := c.namespaceFilter.Load()
	if slices.Equal(previous.include, next.include) && slices.Equal(previous.exclude, next.exclude) &&
		slices.Equal(previous.includePatterns, next.includePatterns) && slices.Equal(previous.excludePatterns, next.excludePatterns) {
		return false, nil
	}
	c.namespaceFilter.Store(next)
	return true, nil
}
