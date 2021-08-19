package mainhandler

import (
	"context"
	"k8s-ca-websocket/cautils"

	"github.com/armosec/capacketsgo/apis"
	pkgcautils "github.com/armosec/capacketsgo/cautils"

	"github.com/armosec/capacketsgo/k8sinterface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func isForceDelete(args map[string]interface{}) bool {
	if args == nil || len(args) == 0 {
		return false
	}
	if v, ok := args["forceDelete"]; ok && v != nil {
		return v.(bool)
	}
	return false
}

func (actionHandler *ActionHandler) deleteConfigMaps(c apis.Command) error {
	confName := pkgcautils.GenarateConfigMapName(actionHandler.wlid)
	return actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).Delete(context.Background(), confName, metav1.DeleteOptions{})
}

func (actionHandler *ActionHandler) workloadCleanupAll() error {
	return actionHandler.cacli.UTILSCleanup(actionHandler.wlid, false)
}
func (actionHandler *ActionHandler) workloadCleanupDiscovery() error {
	return actionHandler.cacli.UTILSCleanup(actionHandler.wlid, true)
}

func persistentVolumeFound(workload k8sinterface.IWorkload) bool {
	volumes, _ := workload.GetVolumes()
	for _, vol := range volumes {
		if vol.PersistentVolumeClaim != nil && vol.PersistentVolumeClaim.ClaimName != "" {
			return true
		}
	}
	return false
}

func RemoveConfigMap(args map[string]interface{}) bool {
	defaultBehavior := true
	if args == nil {
		return defaultBehavior
	}
	if removeConfig, ok := args["removeConfig"]; ok {
		return removeConfig.(bool)
	}
	return defaultBehavior
}
