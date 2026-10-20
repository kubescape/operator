package continuousscanning

import (
	"context"
	"errors"
	"maps"
	"sort"
	"strings"
	"testing"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	armowlid "github.com/armosec/utils-k8s-go/wlid"
	beUtils "github.com/kubescape/backend/pkg/utils"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/names"
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

type rbacObject struct {
	kind, namespace, name string
}

func sa(name string) rbacObject             { return rbacObject{"ServiceAccount", "team", name} }
func role(name string) rbacObject           { return rbacObject{"Role", "team", name} }
func binding(name string) rbacObject        { return rbacObject{"RoleBinding", "team", name} }
func clusterRole(name string) rbacObject    { return rbacObject{"ClusterRole", "", name} }
func clusterBinding(name string) rbacObject { return rbacObject{"ClusterRoleBinding", "", name} }

// tripletRecords returns the scan and the summary the scanner stores for one subject, role
// and binding, the way httphandler/storage writes them: named by the slug of the three,
// labelled with their sanitized names, annotated with the binding's wlid, and the scan
// listing the role and the binding as its related objects.
func tripletRecords(t *testing.T, subject, role, binding rbacObject) []runtime.Object {
	t.Helper()
	name, err := names.RoleBindingResourceToSlug(rbacComponent(subject.kind, subject.namespace, subject.name), rbacComponent(role.kind, role.namespace, role.name), rbacComponent(binding.kind, binding.namespace, binding.name))
	require.NoError(t, err)
	lbls := map[string]string{
		helpersv1.RbacResourceMetadataKey: "true",
		helpersv1.RelatedKindMetadataKey:  subject.kind, helpersv1.RelatedNameMetadataKey: subject.name, helpersv1.RelatedNamespaceMetadataKey: subject.namespace,
	}
	switch role.kind {
	case "Role":
		lbls[helpersv1.RoleNameMetadataKey], lbls[helpersv1.RoleNamespaceMetadataKey] = role.name, role.namespace
	case "ClusterRole":
		lbls[helpersv1.ClusterRoleNameMetadataKey] = role.name
	}
	switch binding.kind {
	case "RoleBinding":
		lbls[helpersv1.RoleBindingNameMetadataKey], lbls[helpersv1.RoleBindingNamespaceMetadataKey] = binding.name, binding.namespace
	case "ClusterRoleBinding":
		lbls[helpersv1.ClusterRoleBindingNameMetadataKey] = binding.name
	}
	names.SanitizeLabelValues(lbls)
	annotations := map[string]string{helpersv1.WlidMetadataKey: armowlid.GetK8sWLID("test", binding.namespace, binding.kind, binding.name)}
	related := []v1beta1.WorkloadScanRelatedObject{
		{Namespace: role.namespace, APIGroup: "rbac.authorization.k8s.io", APIVersion: "v1", Kind: role.kind, Name: role.name},
		{Namespace: binding.namespace, APIGroup: "rbac.authorization.k8s.io", APIVersion: "v1", Kind: binding.kind, Name: binding.name},
	}
	return []runtime.Object{
		&v1beta1.WorkloadConfigurationScan{ObjectMeta: metav1.ObjectMeta{Namespace: kubescapeNamespace, Name: name, Labels: lbls, Annotations: annotations}, Spec: v1beta1.WorkloadConfigurationScanSpec{RelatedObjects: related}},
		&v1beta1.WorkloadConfigurationScanSummary{ObjectMeta: metav1.ObjectMeta{Namespace: kubescapeNamespace, Name: name, Labels: maps.Clone(lbls), Annotations: maps.Clone(annotations)}},
	}
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
	var fixtures []runtime.Object
	fixtures = append(fixtures, tripletRecords(t, sa("app"), role("reader"), binding("app-reader"))...)
	fixtures = append(fixtures, tripletRecords(t, sa("other"), role("writer"), binding("other-writer"))...)
	fixtures = append(fixtures, tripletRecords(t, sa("app"), clusterRole("view"), clusterBinding("app-view"))...)
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
	scanOnly := tripletRecords(t, sa("app"), role("reader"), binding("app-reader"))[:1]
	h, client := newCleaner(t, scanOnly...)
	require.NoError(t, h.deleteScanArtifacts(context.Background(), deletedObject("rbac.authorization.k8s.io/v1", "RoleBinding", "team", "app-reader"), client))
	assert.Empty(t, remainingScans(t, client))
}

// A scan whose delete failed stays discoverable: the next cleanup of the same object finds
// it by its labels even though its summary is gone.
func TestDeletedCleanerRemovesAnRBACScanOnTheNextRunAfterAFailedDelete(t *testing.T) {
	h, client := newCleaner(t, tripletRecords(t, sa("app"), role("reader"), binding("app-reader"))...)
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

// Two objects can share every label the scanner puts on their records: names that differ
// past the 63rd character, and names that differ only in a character the sanitizer maps to
// "-". Deleting one must leave the other's scan and summary alone, whether the record is a
// full scan or a summary whose scan is gone. A summary states its role only by a label, so
// a deleted role leaves it too, to its binding's or subject's deletion.
func TestDeletedCleanerKeepsTheRecordsOfAnObjectWhoseLabelsCollide(t *testing.T) {
	long := strings.Repeat("a", 63)
	rbac := "rbac.authorization.k8s.io/v1"
	tests := []struct {
		name         string
		deleted      *unstructured.Unstructured
		gone, kept   [3]rbacObject
		summaryStays bool
	}{
		{name: "ServiceAccount cut", deleted: deletedObject("v1", "ServiceAccount", "team", long+"x"),
			gone: [3]rbacObject{sa(long + "x"), role("reader"), binding("bx")}, kept: [3]rbacObject{sa(long + "y"), role("reader"), binding("by")}},
		{name: "Role cut", deleted: deletedObject(rbac, "Role", "team", long+"x"),
			gone: [3]rbacObject{sa("app"), role(long + "x"), binding("bx")}, kept: [3]rbacObject{sa("app"), role(long + "y"), binding("by")}, summaryStays: true},
		{name: "Role punctuation", deleted: deletedObject(rbac, "Role", "team", "reader:app"),
			gone: [3]rbacObject{sa("app-a"), role("reader:app"), binding("bind-a")}, kept: [3]rbacObject{sa("app-b"), role("reader-app"), binding("bind-b")}, summaryStays: true},
		{name: "RoleBinding cut", deleted: deletedObject(rbac, "RoleBinding", "team", long+"x"),
			gone: [3]rbacObject{sa("app"), role("reader"), binding(long + "x")}, kept: [3]rbacObject{sa("app"), role("reader"), binding(long + "y")}},
		{name: "RoleBinding punctuation", deleted: deletedObject(rbac, "RoleBinding", "team", "bind:a"),
			gone: [3]rbacObject{sa("app-a"), role("reader"), binding("bind:a")}, kept: [3]rbacObject{sa("app-b"), role("reader"), binding("bind-a")}},
		{name: "ClusterRole cut", deleted: deletedObject(rbac, "ClusterRole", "", long+"x"),
			gone: [3]rbacObject{sa("app"), clusterRole(long + "x"), clusterBinding("bx")}, kept: [3]rbacObject{sa("app"), clusterRole(long + "y"), clusterBinding("by")}, summaryStays: true},
		{name: "ClusterRole punctuation", deleted: deletedObject(rbac, "ClusterRole", "", "system:reader"),
			gone: [3]rbacObject{sa("app-a"), clusterRole("system:reader"), clusterBinding("bind-a")}, kept: [3]rbacObject{sa("app-b"), clusterRole("system-reader"), clusterBinding("bind-b")}, summaryStays: true},
		{name: "ClusterRoleBinding cut", deleted: deletedObject(rbac, "ClusterRoleBinding", "", long+"x"),
			gone: [3]rbacObject{sa("app"), clusterRole("view"), clusterBinding(long + "x")}, kept: [3]rbacObject{sa("app"), clusterRole("view"), clusterBinding(long + "y")}},
		{name: "ClusterRoleBinding punctuation", deleted: deletedObject(rbac, "ClusterRoleBinding", "", "bind:a"),
			gone: [3]rbacObject{sa("app-a"), clusterRole("view"), clusterBinding("bind:a")}, kept: [3]rbacObject{sa("app-b"), clusterRole("view"), clusterBinding("bind-a")}},
	}
	for _, tt := range tests {
		gone := tripletRecords(t, tt.gone[0], tt.gone[1], tt.gone[2])
		kept := tripletRecords(t, tt.kept[0], tt.kept[1], tt.kept[2])
		goneName := kubescapeNamespace + "/" + gone[0].(metav1.Object).GetName()
		keptName := kubescapeNamespace + "/" + kept[0].(metav1.Object).GetName()
		require.NotEqual(t, goneName, keptName, "the scanner stores the two under different names")
		t.Run(tt.name, func(t *testing.T) {
			h, client := newCleaner(t, append(append([]runtime.Object{}, gone...), kept...)...)
			require.NoError(t, h.deleteScanArtifacts(context.Background(), tt.deleted, client))
			assert.Equal(t, []string{keptName}, remainingScans(t, client))
			assert.Equal(t, []string{keptName}, remainingSummaries(t, client))
		})
		t.Run(tt.name+" with the scans gone", func(t *testing.T) {
			h, client := newCleaner(t, gone[1], kept[1])
			require.NoError(t, h.deleteScanArtifacts(context.Background(), tt.deleted, client))
			want := []string{keptName}
			if tt.summaryStays {
				want = append(want, goneName)
				sort.Strings(want)
			}
			assert.Equal(t, want, remainingSummaries(t, client))
		})
	}
}

// A summary whose scan is gone states its role only by a label, so a deleted role leaves
// it; its binding and its subject are stated exactly, and either one's deletion removes it.
func TestDeletedCleanerLeavesASummaryWithoutItsScanToItsBindingOrSubject(t *testing.T) {
	for _, tt := range []struct {
		name    string
		deleted *unstructured.Unstructured
	}{
		{name: "binding", deleted: deletedObject("rbac.authorization.k8s.io/v1", "RoleBinding", "team", "bx")},
		{name: "subject", deleted: deletedObject("v1", "ServiceAccount", "team", "app")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, client := newCleaner(t, tripletRecords(t, sa("app"), role("reader"), binding("bx"))[1:]...)
			require.NoError(t, h.deleteScanArtifacts(context.Background(), deletedObject("rbac.authorization.k8s.io/v1", "Role", "team", "reader"), client))
			assert.Len(t, remainingSummaries(t, client), 1)
			require.NoError(t, h.deleteScanArtifacts(context.Background(), tt.deleted, client))
			assert.Empty(t, remainingSummaries(t, client))
		})
	}
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
