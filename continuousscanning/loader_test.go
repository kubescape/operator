package continuousscanning

import (
	"context"
	"io"
	"testing"
	"errors"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type stubReader struct {
	data []byte
	e error
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
		inputData       []byte
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
			name:      "malformed JSON as input returns error",
			inputDataReader: &stubReader{data: []byte{}, e: nil},
			wantRules: nil,
			wantError: true,
		},
		{
			name:      "reader error returns error",
			inputDataReader: &stubReader{data: []byte(validData), e: errors.New("some error")},
			wantRules: nil,
			wantError: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var f MatchingRuleFetcher
			f = NewFileFetcher(tc.inputDataReader)

			gotRules, gotError := f.Fetch(ctx)

			assert.Equal(t, tc.wantRules, gotRules)
			if tc.wantError {
				assert.Error(t, gotError)
			}
		})
	}
}

type stubFetcher struct {
	data *MatchingRules
}

func (f *stubFetcher) Fetch(ctx context.Context) (*MatchingRules, error) {
	return f.data, nil
}

func TestTargetLoader(t *testing.T) {
	tt := []struct {
		name               string
		inputMatchingRules *MatchingRules
		wantGVRs           []schema.GroupVersionResource
		wantErr            bool
	}{
		{
			name: "single valid GVRs should return appropriate values",
			inputMatchingRules: &MatchingRules{
				APIResources: []APIResourceMatch{
					{
						Groups:    []string{""},
						Versions:  []string{"v1"},
						Resources: []string{"Pod", "ReplicaSet"},
					},
				},
			},
			wantGVRs: []schema.GroupVersionResource{
				{Group: "", Version: "v1", Resource: "Pod"},
				{Group: "", Version: "v1", Resource: "ReplicaSet"},
			},
		},
		{
			name: "single valid GVRs should return appropriate values",
			inputMatchingRules: &MatchingRules{
				APIResources: []APIResourceMatch{
					{
						Groups:    []string{""},
						Versions:  []string{"v1"},
						Resources: []string{"Pod", "ReplicaSet"},
					},
					{
						Groups:    []string{"rbac.authorization.k8s.io"},
						Versions:  []string{"v1"},
						Resources: []string{"ClusterRoleBinding"},
					},
				},
			},
			wantGVRs: []schema.GroupVersionResource{
				{Group: "", Version: "v1", Resource: "Pod"},
				{Group: "", Version: "v1", Resource: "ReplicaSet"},
				{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "ClusterRoleBinding"},
			},
		},
		{
			name: "multiple valid GVRs should return appropriate values",
			inputMatchingRules: &MatchingRules{
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
			},
			wantGVRs: []schema.GroupVersionResource{
				{Group: "", Version: "v1", Resource: "Pod"},
				{Group: "", Version: "v1", Resource: "ReplicaSet"},
				{Group: "", Version: "v2", Resource: "Pod"},
				{Group: "", Version: "v2", Resource: "ReplicaSet"},
				{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "ClusterRoleBinding"},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var fetcher MatchingRuleFetcher
			fetcher = &stubFetcher{tc.inputMatchingRules}
			var l TargetLoader
			l = NewTargetLoader(fetcher)

			gotData := l.LoadGVRs(ctx)

			assert.Equal(t, tc.wantGVRs, gotData)
		})
	}

}
