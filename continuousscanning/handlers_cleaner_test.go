package continuousscanning

import (
	"context"
	"errors"
	"sort"
	"testing"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

const kubescapeNamespace = "kubescape"

func deletedObject(apiVersion, kind, namespace, name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion(apiVersion)
	u.SetKind(kind)
	u.SetNamespace(namespace)
	u.SetName(name)
	return u
}

// postureRecords returns the scan and the summary the scanner stores for one result.
func postureRecords(namespace, name string, lbls map[string]string) []runtime.Object {
	return []runtime.Object{
		&v1beta1.WorkloadConfigurationScan{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: lbls}},
		&v1beta1.WorkloadConfigurationScanSummary{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: lbls}},
	}
}

// rbacRecords returns the records of one subject, role and binding triplet, named and
// labelled the way httphandler/storage names and labels them.
func rbacRecords(name string, extra map[string]string) []runtime.Object {
	lbls := map[string]string{helpersv1.RbacResourceMetadataKey: "true"}
	for k, v := range extra {
		lbls[k] = v
	}
	return postureRecords(kubescapeNamespace, name, lbls)
}

func newCleaner(t *testing.T, objects ...runtime.Object) (*deletedCleanerHandler, *kssfake.Clientset) {
	t.Helper()
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{ClusterName: "test"}, &beUtils.Credentials{}, config.Config{Namespace: kubescapeNamespace})
	require.NoError(t, err)
	client := kssfake.NewSimpleClientset(objects...)
	return &deletedCleanerHandler{clusterConfig: cfg, storageClient: client}, client
}

func remainingSummaries(t *testing.T, client *kssfake.Clientset) []string {
	t.Helper()
	list, err := client.SpdxV1beta1().WorkloadConfigurationScanSummaries("").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	var out []string
	for _, s := range list.Items {
		out = append(out, s.Namespace+"/"+s.Name)
	}
	sort.Strings(out)
	return out
}

func remainingScans(t *testing.T, client *kssfake.Clientset) []string {
	t.Helper()
	list, err := client.SpdxV1beta1().WorkloadConfigurationScans("").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	var out []string
	for _, s := range list.Items {
		out = append(out, s.Namespace+"/"+s.Name)
	}
	sort.Strings(out)
	return out
}

func TestDeletedCleanerRemovesTheRecordsOfADeletedObject(t *testing.T) {
	saTriplet := map[string]string{
		helpersv1.RelatedKindMetadataKey: "ServiceAccount", helpersv1.RelatedNameMetadataKey: "app", helpersv1.RelatedNamespaceMetadataKey: "team",
		helpersv1.RoleNameMetadataKey: "reader", helpersv1.RoleNamespaceMetadataKey: "team",
		helpersv1.RoleBindingNameMetadataKey: "app-reader", helpersv1.RoleBindingNamespaceMetadataKey: "team",
	}
	otherTriplet := map[string]string{
		helpersv1.RelatedKindMetadataKey: "ServiceAccount", helpersv1.RelatedNameMetadataKey: "other", helpersv1.RelatedNamespaceMetadataKey: "team",
		helpersv1.RoleNameMetadataKey: "writer", helpersv1.RoleNamespaceMetadataKey: "team",
		helpersv1.RoleBindingNameMetadataKey: "other-writer", helpersv1.RoleBindingNamespaceMetadataKey: "team",
	}
	clusterTriplet := map[string]string{
		helpersv1.RelatedKindMetadataKey: "ServiceAccount", helpersv1.RelatedNameMetadataKey: "app", helpersv1.RelatedNamespaceMetadataKey: "team",
		helpersv1.ClusterRoleNameMetadataKey: "view", helpersv1.ClusterRoleBindingNameMetadataKey: "app-view",
	}
	var fixtures []runtime.Object
	fixtures = append(fixtures, rbacRecords("serviceaccount-app-role-reader-rolebinding-app-reader", saTriplet)...)
	fixtures = append(fixtures, rbacRecords("serviceaccount-other-role-writer-rolebinding-other-writer", otherTriplet)...)
	fixtures = append(fixtures, rbacRecords("serviceaccount-app-clusterrole-view-clusterrolebinding-app-view", clusterTriplet)...)
	fixtures = append(fixtures, postureRecords("team", "serviceaccount-app", nil)...)
	fixtures = append(fixtures, postureRecords("team", "secret-token", nil)...)
	fixtures = append(fixtures, postureRecords(kubescapeNamespace, "node-worker-1", nil)...)
	fixtures = append(fixtures, postureRecords(kubescapeNamespace, "clusterrole-view", nil)...)
	all := func() []string {
		return []string{
			"kubescape/clusterrole-view", "kubescape/node-worker-1",
			"kubescape/serviceaccount-app-clusterrole-view-clusterrolebinding-app-view",
			"kubescape/serviceaccount-app-role-reader-rolebinding-app-reader",
			"kubescape/serviceaccount-other-role-writer-rolebinding-other-writer",
			"team/secret-token", "team/serviceaccount-app",
		}
	}
	without := func(gone ...string) []string {
		var out []string
		for _, s := range all() {
			keep := true
			for _, g := range gone {
				if s == g {
					keep = false
				}
			}
			if keep {
				out = append(out, s)
			}
		}
		return out
	}

	tests := []struct {
		name    string
		deleted *unstructured.Unstructured
		want    []string
	}{
		{name: "a RoleBinding takes the records of every triplet it binds",
			deleted: deletedObject("rbac.authorization.k8s.io/v1", "RoleBinding", "team", "app-reader"),
			want:    without("kubescape/serviceaccount-app-role-reader-rolebinding-app-reader")},
		{name: "a Role takes the records of the triplets that use it",
			deleted: deletedObject("rbac.authorization.k8s.io/v1", "Role", "team", "writer"),
			want:    without("kubescape/serviceaccount-other-role-writer-rolebinding-other-writer")},
		{name: "a ClusterRoleBinding is found by its own label",
			deleted: deletedObject("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", "app-view"),
			want:    without("kubescape/serviceaccount-app-clusterrole-view-clusterrolebinding-app-view")},
		{name: "a ClusterRole takes its own record and the triplets that use it",
			deleted: deletedObject("rbac.authorization.k8s.io/v1", "ClusterRole", "", "view"),
			want:    without("kubescape/clusterrole-view", "kubescape/serviceaccount-app-clusterrole-view-clusterrolebinding-app-view")},
		{name: "a ServiceAccount takes its own record and the triplets it is the subject of",
			deleted: deletedObject("v1", "ServiceAccount", "team", "app"),
			want: without("team/serviceaccount-app",
				"kubescape/serviceaccount-app-role-reader-rolebinding-app-reader",
				"kubescape/serviceaccount-app-clusterrole-view-clusterrolebinding-app-view")},
		{name: "a cluster-scoped object is looked up in the kubescape namespace",
			deleted: deletedObject("v1", "Node", "", "worker-1"),
			want:    without("kubescape/node-worker-1")},
		{name: "a namespaced object without a vulnerability summary is no error",
			deleted: deletedObject("v1", "Secret", "team", "token"),
			want:    without("team/secret-token")},
		{name: "an object without records is no error",
			deleted: deletedObject("v1", "ConfigMap", "team", "settings"),
			want:    all()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, client := newCleaner(t, fixtures...)
			require.NoError(t, h.deleteScanArtifacts(context.Background(), tt.deleted, client))
			assert.Equal(t, tt.want, remainingSummaries(t, client))
			assert.Equal(t, tt.want, remainingScans(t, client), "scans and summaries go together")
		})
	}
}

func TestDeletedCleanerReportsTheFirstRealErrorAfterTryingEverything(t *testing.T) {
	h, client := newCleaner(t, postureRecords("team", "secret-token", nil)...)
	boom := errors.New("storage unavailable")
	client.PrependReactor("delete", "workloadconfigurationscans", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, boom
	})
	err := h.deleteScanArtifacts(context.Background(), deletedObject("v1", "Secret", "team", "token"), client)
	require.ErrorIs(t, err, boom)
	assert.Empty(t, remainingSummaries(t, client), "the summary is still removed after the scan delete failed")
}

// An RBAC scan is found through its own labels, not through its summary, so one whose
// summary is already gone is still removed.
func TestDeletedCleanerFindsAnRBACScanWithoutItsSummary(t *testing.T) {
	triplet := map[string]string{
		helpersv1.RelatedKindMetadataKey: "ServiceAccount", helpersv1.RelatedNameMetadataKey: "app", helpersv1.RelatedNamespaceMetadataKey: "team",
		helpersv1.RoleBindingNameMetadataKey: "app-reader", helpersv1.RoleBindingNamespaceMetadataKey: "team",
	}
	scanOnly := rbacRecords("serviceaccount-app-role-reader-rolebinding-app-reader", triplet)[:1]
	h, client := newCleaner(t, scanOnly...)
	require.NoError(t, h.deleteScanArtifacts(context.Background(), deletedObject("rbac.authorization.k8s.io/v1", "RoleBinding", "team", "app-reader"), client))
	assert.Empty(t, remainingScans(t, client))
}

// A scan whose delete failed stays discoverable: the next cleanup of the same object finds
// it by its labels even though its summary is gone.
func TestDeletedCleanerRemovesAnRBACScanOnTheNextRunAfterAFailedDelete(t *testing.T) {
	triplet := map[string]string{
		helpersv1.RelatedKindMetadataKey: "ServiceAccount", helpersv1.RelatedNameMetadataKey: "app", helpersv1.RelatedNamespaceMetadataKey: "team",
		helpersv1.RoleBindingNameMetadataKey: "app-reader", helpersv1.RoleBindingNamespaceMetadataKey: "team",
	}
	h, client := newCleaner(t, rbacRecords("serviceaccount-app-role-reader-rolebinding-app-reader", triplet)...)
	boom := errors.New("storage unavailable")
	failed := false
	client.PrependReactor("delete", "workloadconfigurationscans", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if failed || action.(k8stesting.DeleteAction).GetName() != "serviceaccount-app-role-reader-rolebinding-app-reader" {
			return false, nil, nil
		}
		failed = true
		return true, nil, boom
	})
	deleted := deletedObject("rbac.authorization.k8s.io/v1", "RoleBinding", "team", "app-reader")

	err := h.deleteScanArtifacts(context.Background(), deleted, client)
	require.ErrorIs(t, err, boom)
	assert.Equal(t, []string{"kubescape/serviceaccount-app-role-reader-rolebinding-app-reader"}, remainingScans(t, client))
	assert.Empty(t, remainingSummaries(t, client), "the summary delete is still attempted")

	require.NoError(t, h.deleteScanArtifacts(context.Background(), deleted, client))
	assert.Empty(t, remainingScans(t, client))
}

func TestRBACRecordSelector(t *testing.T) {
	tests := []struct {
		kind, namespace, name string
		want                  string
	}{
		{"RoleBinding", "team", "app-reader", "kubescape.io/rbac-resource=true,kubescape.io/rolebinding-name=app-reader,kubescape.io/rolebinding-namespace=team"},
		{"Role", "team", "reader", "kubescape.io/rbac-resource=true,kubescape.io/role-name=reader,kubescape.io/role-namespace=team"},
		{"ClusterRoleBinding", "", "app-view", "kubescape.io/clusterrolebinding-name=app-view,kubescape.io/rbac-resource=true"},
		{"ClusterRole", "", "view", "kubescape.io/clusterrole-name=view,kubescape.io/rbac-resource=true"},
		{"ServiceAccount", "team", "app", "kubescape.io/rbac-resource=true,kubescape.io/workload-kind=ServiceAccount,kubescape.io/workload-name=app,kubescape.io/workload-namespace=team"},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			selector, ok := rbacRecordSelector(deletedObject("v1", tt.kind, tt.namespace, tt.name))
			require.True(t, ok)
			assert.Equal(t, tt.want, selector.String())
		})
	}
	_, ok := rbacRecordSelector(deletedObject("apps/v1", "Deployment", "team", "web"))
	assert.False(t, ok, "a workload takes part in no RBAC record")
}
