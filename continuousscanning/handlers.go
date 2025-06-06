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
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/k8s-interface/workloadinterface"
	opautilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"github.com/panjf2000/ants/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

func (h *deletedCleanerHandler) getObjectNamespace(uObject *unstructured.Unstructured, fallback string) string {
	ns := uObject.GetNamespace()
	if ns != "" {
		return ns
	}
	return fallback
}

func (h *deletedCleanerHandler) getObjectName(uObject *unstructured.Unstructured) (string, error) {
	kind := uObject.GetKind()
	wl := workloadinterface.NewWorkloadObj(uObject.Object)

	var slug string
	if kind == "RoleBinding" {
		slug, _ = names.ResourceToSlug(wl)
	}

	slug, err := names.ResourceToSlug(wl)
	if err != nil {
		return "", err
	}

	return slug, nil
}

func (h *deletedCleanerHandler) deleteScanArtifacts(ctx context.Context, uObject *unstructured.Unstructured, storageClient kssc.Interface) error {
	nsFallback := ""
	ns := h.getObjectNamespace(uObject, nsFallback)
	name, err := h.getObjectName(uObject)
	if err != nil {
		return fmt.Errorf("failed to get object name: %w", err)
	}

	err = storageClient.SpdxV1beta1().WorkloadConfigurationScans(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete workload configuration: %w", err)
	}

	err = storageClient.SpdxV1beta1().WorkloadConfigurationScanSummaries(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete workload configuration summary: %w", err)
	}

	err = storageClient.SpdxV1beta1().VulnerabilityManifestSummaries(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete vulnerability manifest summary: %w", err)
	}
	return nil
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
