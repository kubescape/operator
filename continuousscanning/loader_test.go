package continuousscanning

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestTargetFetcher(t *testing.T) {
	tt := []struct {
		name         string
		inputObjects []runtime.Object
		wantData     MatchingRules
		wantErr      bool
	}{
		{
			name: "existing valid configmap should return appropriate values",
			inputObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kubescape-config",
						Namespace: "kubescape",
					},
					BinaryData: map[string][]byte{
						"matches.json": []byte(
							`{
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
}
`,
						),
					},
				},
			},
			wantData: MatchingRules{
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
			name: "misnamed configmap key should return an error",
			inputObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kubescape-config",
						Namespace: "kubescape",
					},
					BinaryData: map[string][]byte{
						"not-matches.json": []byte(
							`{
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
}
`,
						),
					},
				},
			},
			wantData: MatchingRules{},
			wantErr:  true,
		},
		{
			name: "malformed configmap should return an error",
			inputObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kubescape-config",
						Namespace: "kubescape",
					},
					BinaryData: map[string][]byte{
						"matches.json": []byte(
							`{`,
						),
					},
				},
			},
			wantData: MatchingRules{},
			wantErr:  true,
		},
		{
			name:         "missing configmap should return empty values and matching error",
			inputObjects: []runtime.Object{},
			wantData:     MatchingRules{},
			wantErr:      true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			k8sClient := k8sfake.NewSimpleClientset(tc.inputObjects...)
			l := NewConfigMapTargetFetcher(k8sClient)

			gotData, gotErr := l.Fetch(ctx)

			assert.Equal(t, tc.wantData, gotData)
			if tc.wantErr {
				assert.Error(t, gotErr)
			}
		})
	}

}

type stubFetcher struct {
	data MatchingRules
}

func (f *stubFetcher) Fetch(ctx context.Context) (MatchingRules, error) {
	return f.data, nil
}

func TestTargetLoader(t *testing.T) {
	tt := []struct {
		name               string
		inputMatchingRules MatchingRules
		wantGVRs           []schema.GroupVersionResource
		wantErr            bool
	}{
		{
			name: "single valid GVRs should return appropriate values",
			inputMatchingRules: MatchingRules{
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
			inputMatchingRules: MatchingRules{
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
			inputMatchingRules: MatchingRules{
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
			fetcher := &stubFetcher{tc.inputMatchingRules}
			l := NewTargetLoader(fetcher)

			gotData := l.LoadGVRs(ctx)

			assert.Equal(t, tc.wantGVRs, gotData)
		})
	}

}
