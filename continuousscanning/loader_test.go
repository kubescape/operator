package continuousscanning

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type stubReader struct {
	data []byte
	e    error
}

func (r stubReader) Read(p []byte) (int, error) {
	if r.e != nil {
		return 0, r.e
	}
	n := copy(p, r.data)
	return n, io.EOF
}

func TestFileFetcher(t *testing.T) {
	validData := `{
	"match": [
		{
			"apiGroups": [],
			"apiVersions": ["v1"],
			"resources": ["Deployment"]
		},
		{
			"apiGroups": ["rbac.authorization.k8s.io"],
			"apiVersions": ["v1"],
			"resources": ["ClusterRoleBinding"]
		}
	],
	"namespaces": ["kube-system", "default"]
}`
	tt := []struct {
		name            string
		inputDataReader io.Reader
		wantRules       *MatchingRules
		wantError       bool
	}{
		{
			name:            "valid data parses correctly",
			inputDataReader: &stubReader{data: []byte(validData), e: nil},
			wantRules: &MatchingRules{
				APIResources: []APIResourceMatch{
					{
						Groups:    []string{},
						Versions:  []string{"v1"},
						Resources: []string{"Deployment"},
					},
					{
						Groups:    []string{"rbac.authorization.k8s.io"},
						Versions:  []string{"v1"},
						Resources: []string{"ClusterRoleBinding"},
					},
				},
				Namespaces: []string{"kube-system", "default"},
			},
		},
		{
			name:            "malformed JSON as input returns error",
			inputDataReader: &stubReader{data: []byte{}, e: nil},
			wantRules:       nil,
			wantError:       true,
		},
		{
			name:            "reader error returns error",
			inputDataReader: &stubReader{data: []byte(validData), e: errors.New("some error")},
			wantRules:       nil,
			wantError:       true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f := MatchingRuleFetcher(NewFileFetcher(tc.inputDataReader))

			gotRules, gotError := f.Fetch(ctx)

			assert.Equal(t, tc.wantRules, gotRules)
			if tc.wantError {
				assert.Error(t, gotError)
			}
		})
	}
}

func TestParseMatchingRules(t *testing.T) {
	chartDefault := `{
	"match": [
		{
			"apiGroups": ["apps"],
			"apiVersions": ["v1"],
			"resources": ["deployments"]
		}
	],
	"namespaces": ["default"]
}`
	tt := []struct {
		name      string
		input     string
		wantError bool
		wantRules *MatchingRules
	}{
		{
			name:      "null",
			input:     "null",
			wantError: true,
		},
		{
			name:      "whitespace plus null",
			input:     "  null  ",
			wantError: true,
		},
		{
			name:      "malformed JSON",
			input:     "{not json",
			wantError: true,
		},
		{
			name:      "empty file",
			input:     "",
			wantError: true,
		},
		{
			name:      "whitespace-only file",
			input:     "   \n\t  ",
			wantError: true,
		},
		{
			name:  "explicitly empty match",
			input: `{"match":[]}`,
			wantRules: &MatchingRules{
				APIResources: []APIResourceMatch{},
			},
		},
		{
			name:  "chart default",
			input: chartDefault,
			wantRules: &MatchingRules{
				APIResources: []APIResourceMatch{
					{
						Groups:    []string{"apps"},
						Versions:  []string{"v1"},
						Resources: []string{"deployments"},
					},
				},
				Namespaces: []string{"default"},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseMatchingRules(strings.NewReader(tc.input))
			if tc.wantError {
				require.Error(t, err)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantRules, got)
		})
	}
}

type stubFetcher struct {
	data *MatchingRules
	err  error
}

func (f *stubFetcher) Fetch(ctx context.Context) (*MatchingRules, error) {
	return f.data, f.err
}

type countingFetcher struct {
	calls atomic.Int32
	data  *MatchingRules
	err   error
}

func (f *countingFetcher) Fetch(ctx context.Context) (*MatchingRules, error) {
	f.calls.Add(1)
	return f.data, f.err
}

func TestTargetLoaderLoad(t *testing.T) {
	chartDefault := `{
	"match": [
		{
			"apiGroups": ["apps"],
			"apiVersions": ["v1"],
			"resources": ["deployments"]
		}
	],
	"namespaces": ["default", "kube-system"]
}`

	tt := []struct {
		name           string
		fetcher        MatchingRuleFetcher
		wantGVRs       []schema.GroupVersionResource
		wantNamespaces []string
		wantErr        bool
		errContains    string
	}{
		{
			name:    "null JSON",
			fetcher: NewFileFetcher(strings.NewReader("null")),
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			fetcher: NewFileFetcher(strings.NewReader("{not json")),
			wantErr: true,
		},
		{
			name:    "empty file",
			fetcher: NewFileFetcher(strings.NewReader("")),
			wantErr: true,
		},
		{
			name:           "explicitly empty match",
			fetcher:        NewFileFetcher(strings.NewReader(`{"match":[]}`)),
			wantGVRs:       []schema.GroupVersionResource{},
			wantNamespaces: nil,
		},
		{
			name:    "chart default with namespaces",
			fetcher: NewFileFetcher(strings.NewReader(chartDefault)),
			wantGVRs: []schema.GroupVersionResource{
				{Group: "apps", Version: "v1", Resource: "deployments"},
			},
			wantNamespaces: []string{"default", "kube-system"},
		},
		{
			name: "single valid GVRs",
			fetcher: &stubFetcher{data: &MatchingRules{
				APIResources: []APIResourceMatch{
					{
						Groups:    []string{""},
						Versions:  []string{"v1"},
						Resources: []string{"Pod", "ReplicaSet"},
					},
				},
			}},
			wantGVRs: []schema.GroupVersionResource{
				{Group: "", Version: "v1", Resource: "Pod"},
				{Group: "", Version: "v1", Resource: "ReplicaSet"},
			},
		},
		{
			name: "multiple groups and versions",
			fetcher: &stubFetcher{data: &MatchingRules{
				APIResources: []APIResourceMatch{
					{
						Groups:    []string{""},
						Versions:  []string{"v1", "v2"},
						Resources: []string{"Pod", "ReplicaSet"},
					},
					{
						Groups:    []string{"rbac.authorization.k8s.io"},
						Versions:  []string{"v1"},
						Resources: []string{"ClusterRoleBinding"},
					},
				},
			}},
			wantGVRs: []schema.GroupVersionResource{
				{Group: "", Version: "v1", Resource: "Pod"},
				{Group: "", Version: "v1", Resource: "ReplicaSet"},
				{Group: "", Version: "v2", Resource: "Pod"},
				{Group: "", Version: "v2", Resource: "ReplicaSet"},
				{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "ClusterRoleBinding"},
			},
		},
		{
			name:        "fetcher returns nil nil",
			fetcher:     &stubFetcher{data: nil, err: nil},
			wantErr:     true,
			errContains: "matching rules are null",
		},
		{
			name:        "fetcher returns error",
			fetcher:     &stubFetcher{data: nil, err: errors.New("boom")},
			wantErr:     true,
			errContains: "boom",
		},
		{
			name: "configured namespaces are returned",
			fetcher: &stubFetcher{data: &MatchingRules{
				APIResources: []APIResourceMatch{
					{
						Groups:    []string{"apps"},
						Versions:  []string{"v1"},
						Resources: []string{"deployments"},
					},
				},
				Namespaces: []string{"default", "kube-system"},
			}},
			wantGVRs: []schema.GroupVersionResource{
				{Group: "apps", Version: "v1", Resource: "deployments"},
			},
			wantNamespaces: []string{"default", "kube-system"},
		},
		{
			name: "no namespaces means every namespace",
			fetcher: &stubFetcher{data: &MatchingRules{
				APIResources: []APIResourceMatch{
					{
						Groups:    []string{"apps"},
						Versions:  []string{"v1"},
						Resources: []string{"deployments"},
					},
				},
			}},
			wantGVRs: []schema.GroupVersionResource{
				{Group: "apps", Version: "v1", Resource: "deployments"},
			},
			wantNamespaces: nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Load panicked: %v", r)
				}
			}()

			ctx := context.Background()
			l := NewTargetLoader(tc.fetcher)

			gotGVRs, gotNamespaces, err := l.Load(ctx)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.ErrorContains(t, err, tc.errContains)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantGVRs, gotGVRs)
			assert.Equal(t, tc.wantNamespaces, gotNamespaces)
		})
	}
}

func TestTargetLoaderLoad_SingleFetch(t *testing.T) {
	fetcher := &countingFetcher{
		data: &MatchingRules{
			APIResources: []APIResourceMatch{
				{
					Groups:    []string{"apps"},
					Versions:  []string{"v1"},
					Resources: []string{"deployments"},
				},
			},
			Namespaces: []string{"default"},
		},
	}
	l := NewTargetLoader(fetcher)

	_, _, err := l.Load(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(1), fetcher.calls.Load())
}
