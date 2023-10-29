package continuousscanning

import (
	"context"
	"errors"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"

	armoapi "github.com/armosec/armoapi-go/apis"
	armowlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	opautilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
)

type EventHandler interface {
	Handle(ctx context.Context, e watch.Event) error
}

type poolInvokerHandler struct {
	wp                   *ants.PoolWithFunc
	clusterConfig        utilsmetadata.ClusterConfig
	eventReceiverRestURL string
}

func makeScanArgs(so *objectsenvelopes.ScanObject, isDeletedSO bool) map[string]interface{} {
	psr := opautilsmetav1.PostScanRequest{
		ScanObject:          so,
		IsDeletedScanObject: &isDeletedSO,
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

func triggerScan(ctx context.Context, wp *ants.PoolWithFunc, eventReceiverRestURL string, clusterConfig utilsmetadata.ClusterConfig, command *armoapi.Command) error {
	utils.AddCommandToChannel(ctx, eventReceiverRestURL, clusterConfig, command, wp)
	return nil
}

func unstructuredToScanObject(uObject *unstructured.Unstructured) (*objectsenvelopes.ScanObject, error) {
	var res *objectsenvelopes.ScanObject
	if res = objectsenvelopes.NewScanObject(uObject.UnstructuredContent()); res == nil {
		return res, errors.New("passed object cannot be converted to ScanObject")
	}
	return res, nil
}

func triggerScanFor(ctx context.Context, uObject *unstructured.Unstructured, isDelete bool, wp *ants.PoolWithFunc, eventReceiverRestURL string, clusterConfig utilsmetadata.ClusterConfig) error {
	logger.L().Ctx(ctx).Info(
		"triggering scan",
		helpers.String("clusterName", clusterConfig.ClusterName),
	)
	sc := makeScanCommand(clusterConfig.ClusterName, uObject, isDelete)
	return triggerScan(ctx, wp, eventReceiverRestURL, clusterConfig, sc)
}

func (h *poolInvokerHandler) Handle(ctx context.Context, e watch.Event) error {
	// Process only ADDED and MODIFIED events
	if e.Type != watch.Added && e.Type != watch.Modified {
		return nil
	}
	isDelete := false

	uObject, err := eventToUnstructured(e)
	if err != nil {
		return err
	}

	return triggerScanFor(ctx, uObject, isDelete, h.wp, h.eventReceiverRestURL, h.clusterConfig)
}

func NewTriggeringHandler(wp *ants.PoolWithFunc, clusterConfig utilsmetadata.ClusterConfig, eventReceiverRestURL string) EventHandler {
	return &poolInvokerHandler{wp: wp, clusterConfig: clusterConfig, eventReceiverRestURL: eventReceiverRestURL}
}
