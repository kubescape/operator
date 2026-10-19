package continuousscanning

import (
	"context"
	"errors"
	"fmt"

	armoapi "github.com/armosec/armoapi-go/apis"
	armowlid "github.com/armosec/utils-k8s-go/wlid"
	sets "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/k8s-interface/workloadinterface"
	opautilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"github.com/panjf2000/ants/v2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/utils/ptr"
)

var orphanableWorkloadTypes = sets.NewSet[string]("Pod", "ReplicaSet", "Job")

type EventHandler interface {
	Handle(ctx context.Context, e watch.Event) error
}

type poolInvokerHandler struct {
	wp            *ants.PoolWithFunc
	clusterConfig config.IConfig
}

func makeScanArgs(so *objectsenvelopes.ScanObject, isDeletedSO bool) map[string]interface{} {
	psr := opautilsmetav1.PostScanRequest{
		ScanObject:          so,
		IsDeletedScanObject: &isDeletedSO,
		HostScanner:         ptr.To(false),
	}

	return map[string]interface{}{
		utils.KubescapeScanV1: psr,
	}

}

func extractWlid(clusterName string, uObject *unstructured.Unstructured) string {
	kind := uObject.GetKind()
	name := uObject.GetName()
	ns := uObject.GetNamespace()
	return armowlid.GetK8sWLID(clusterName, ns, kind, name)
}

func makeScanCommand(clusterName string, uObject *unstructured.Unstructured, isDelete bool) *armoapi.Command {
	wlid := extractWlid(clusterName, uObject)

	scanObject, _ := unstructuredToScanObject(uObject)

	args := makeScanArgs(scanObject, isDelete)

	return &armoapi.Command{
		CommandName: armoapi.TypeRunKubescape,
		Wlid:        wlid,
		Args:        args,
	}
}

// eventToUnstructured converts a K8s event to an unstructured.Unstructured object
func eventToUnstructured(e watch.Event) (*unstructured.Unstructured, error) {
	obj := e.Object.(*unstructured.Unstructured)
	objRaw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}

	return &unstructured.Unstructured{Object: objRaw}, nil
}

func triggerScan(ctx context.Context, wp *ants.PoolWithFunc, clusterConfig config.IConfig, command *armoapi.Command) error {

	return utils.AddCommandToChannel(ctx, clusterConfig, command, wp)
}

func unstructuredToScanObject(uObject *unstructured.Unstructured) (*objectsenvelopes.ScanObject, error) {
	var res *objectsenvelopes.ScanObject
	if res = objectsenvelopes.NewScanObject(uObject.UnstructuredContent()); res == nil {
		return res, errors.New("passed object cannot be converted to ScanObject")
	}
	return res, nil
}

func triggerScanFor(ctx context.Context, uObject *unstructured.Unstructured, isDelete bool, wp *ants.PoolWithFunc, clusterConfig config.IConfig) error {
	logger.L().Info(
		"triggering scan",
		helpers.String("kind", uObject.GetKind()),
		helpers.String("name", uObject.GetName()),
		helpers.String("namespace", uObject.GetNamespace()),
	)
	sc := makeScanCommand(clusterConfig.ClusterName(), uObject, isDelete)
	return triggerScan(ctx, wp, clusterConfig, sc)
}

func isOrphanWorkloadType(uObject *unstructured.Unstructured) bool {
	kind := uObject.GetKind()
	return orphanableWorkloadTypes.Contains(kind)
}

func isOrphanWorkload(uObject *unstructured.Unstructured) bool {
	wlObject := workloadinterface.NewWorkloadObj(uObject.Object)
	return isOrphanWorkloadType(uObject) && k8sinterface.WorkloadHasParent(wlObject)
}

func (h *poolInvokerHandler) Handle(ctx context.Context, e watch.Event) error {
	// Process only ADDED and MODIFIED events
	if e.Type != watch.Added && e.Type != watch.Modified {
		return nil
	}

	uObject, err := eventToUnstructured(e)
	if err != nil {
		return err
	}

	// Don't trigger scans for orphan workloads
	if isOrphanWorkload(uObject) {
		return nil
	}

	return triggerScanFor(ctx, uObject, false, h.wp, h.clusterConfig)
}

func NewTriggeringHandler(wp *ants.PoolWithFunc, clusterConfig config.IConfig) EventHandler {
	return &poolInvokerHandler{wp: wp, clusterConfig: clusterConfig}
}

func NewDeletedCleanerHandler(wp *ants.PoolWithFunc, clusterConfig config.IConfig, storageClient kssc.Interface) EventHandler {
	return &deletedCleanerHandler{
		wp:            wp,
		clusterConfig: clusterConfig,
		storageClient: storageClient,
	}
}

// deletedCleanerHandler cleans up deleted resources in the Storage
type deletedCleanerHandler struct {
	wp            *ants.PoolWithFunc
	clusterConfig config.IConfig
	storageClient kssc.Interface
}

// getObjectNamespace is the namespace the scanner stored the object's records in: its own
// for a namespaced object, fallback for a cluster-scoped one.
func (h *deletedCleanerHandler) getObjectNamespace(uObject *unstructured.Unstructured, fallback string) string {
	ns := uObject.GetNamespace()
	if ns != "" {
		return ns
	}
	return fallback
}

func (h *deletedCleanerHandler) getObjectName(uObject *unstructured.Unstructured) (string, error) {
	return names.ResourceToSlug(workloadinterface.NewWorkloadObj(uObject.Object))
}

// rbacRecordSelector selects the RBAC records that name the object as their subject, role or
// binding. Those records are stored in the kubescape namespace under a name built from all
// three, so they can only be found through the labels the scanner puts on them. Objects that
// take no part in RBAC records select nothing.
func rbacRecordSelector(uObject *unstructured.Unstructured) (labels.Selector, bool) {
	set := labels.Set{helpersv1.RbacResourceMetadataKey: "true"}
	name, namespace := names.ToValidLabelValue(uObject.GetName()), names.ToValidLabelValue(uObject.GetNamespace())
	switch uObject.GetKind() {
	case "RoleBinding":
		set[helpersv1.RoleBindingNameMetadataKey] = name
		set[helpersv1.RoleBindingNamespaceMetadataKey] = namespace
	case "ClusterRoleBinding":
		set[helpersv1.ClusterRoleBindingNameMetadataKey] = name
	case "Role":
		set[helpersv1.RoleNameMetadataKey] = name
		set[helpersv1.RoleNamespaceMetadataKey] = namespace
	case "ClusterRole":
		set[helpersv1.ClusterRoleNameMetadataKey] = name
	case "ServiceAccount":
		set[helpersv1.RelatedKindMetadataKey] = "ServiceAccount"
		set[helpersv1.RelatedNameMetadataKey] = name
		set[helpersv1.RelatedNamespaceMetadataKey] = namespace
	default:
		return nil, false
	}
	return labels.SelectorFromSet(set), true
}

// deleteScanArtifacts removes the posture and vulnerability records the scanner stored for
// the deleted object: the ones named after it, in its namespace or in the kubescape namespace
// when it is cluster-scoped, and the RBAC records it took part in. Scans and summaries are
// listed separately, so a record whose counterpart is already gone is still found. A record
// that is not there is not an error; the first other error is returned once everything was
// attempted.
func (h *deletedCleanerHandler) deleteScanArtifacts(ctx context.Context, uObject *unstructured.Unstructured, storageClient kssc.Interface) error {
	kubescapeNamespace := h.clusterConfig.Namespace()
	ns := h.getObjectNamespace(uObject, kubescapeNamespace)
	name, err := h.getObjectName(uObject)
	if err != nil {
		return fmt.Errorf("failed to get object name: %w", err)
	}

	var firstErr error
	attempt := func(what string, err error) {
		if err == nil || apierrors.IsNotFound(err) {
			return
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("failed to delete %s: %w", what, err)
		}
	}
	deletePosture := func(namespace, name string) {
		attempt("workload configuration", storageClient.SpdxV1beta1().WorkloadConfigurationScans(namespace).Delete(ctx, name, metav1.DeleteOptions{}))
		attempt("workload configuration summary", storageClient.SpdxV1beta1().WorkloadConfigurationScanSummaries(namespace).Delete(ctx, name, metav1.DeleteOptions{}))
	}

	deletePosture(ns, name)
	attempt("vulnerability manifest summary", storageClient.SpdxV1beta1().VulnerabilityManifestSummaries(ns).Delete(ctx, name, metav1.DeleteOptions{}))

	if selector, ok := rbacRecordSelector(uObject); ok {
		opts := metav1.ListOptions{LabelSelector: selector.String()}
		scans, err := storageClient.SpdxV1beta1().WorkloadConfigurationScans(kubescapeNamespace).List(ctx, opts)
		if err != nil {
			attempt("list of RBAC workload configurations", err)
		}
		for i := range scans.Items {
			attempt("workload configuration", storageClient.SpdxV1beta1().WorkloadConfigurationScans(kubescapeNamespace).Delete(ctx, scans.Items[i].Name, metav1.DeleteOptions{}))
		}
		summaries, err := storageClient.SpdxV1beta1().WorkloadConfigurationScanSummaries(kubescapeNamespace).List(ctx, opts)
		if err != nil {
			attempt("list of RBAC workload configuration summaries", err)
		}
		for i := range summaries.Items {
			attempt("workload configuration summary", storageClient.SpdxV1beta1().WorkloadConfigurationScanSummaries(kubescapeNamespace).Delete(ctx, summaries.Items[i].Name, metav1.DeleteOptions{}))
		}
	}
	return firstErr
}

func (h *deletedCleanerHandler) deleteCRDs(ctx context.Context, uObject *unstructured.Unstructured, storageClient kssc.Interface) error {
	switch uObject.GetKind() {
	default:
		return h.deleteScanArtifacts(ctx, uObject, storageClient)
	}
}

func (h *deletedCleanerHandler) Handle(ctx context.Context, e watch.Event) error {
	// Handle only DELETED events
	if e.Type != watch.Deleted {
		return nil
	}

	uObject, err := eventToUnstructured(e)
	if err != nil {
		return err
	}

	// Don't trigger scans for orphan workloads
	if isOrphanWorkload(uObject) {
		return nil
	}

	err = h.deleteCRDs(ctx, uObject, h.storageClient)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to delete CRDs", helpers.Error(err))
	}

	err = triggerScanFor(ctx, uObject, true, h.wp, h.clusterConfig)
	return err
}
