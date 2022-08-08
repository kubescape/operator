package mainhandler

import (
	"fmt"
	"k8s-ca-websocket/utils"
	"net/http"
	"strings"
	"time"

	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-k8s-go/probes"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"

	"github.com/armosec/k8s-interface/k8sinterface"
)

var IgnoreCommandInNamespace = map[apis.NotificationPolicyType][]string{}

func InitIgnoreCommandInNamespace() {
	if len(IgnoreCommandInNamespace) != 0 {
		return
	}
	IgnoreCommandInNamespace[apis.TypeUpdateWorkload] = []string{metav1.NamespaceSystem, metav1.NamespacePublic, utils.Namespace}
	IgnoreCommandInNamespace[apis.TypeInjectToWorkload] = []string{metav1.NamespaceSystem, metav1.NamespacePublic, utils.Namespace}
	IgnoreCommandInNamespace[apis.TypeDecryptSecret] = []string{metav1.NamespaceSystem, metav1.NamespacePublic, utils.Namespace}
	IgnoreCommandInNamespace[apis.TypeEncryptSecret] = []string{metav1.NamespaceSystem, metav1.NamespacePublic, utils.Namespace}
	IgnoreCommandInNamespace[apis.TypeRemoveWorkload] = []string{metav1.NamespaceSystem, metav1.NamespacePublic, utils.Namespace}
	IgnoreCommandInNamespace[apis.TypeRestartWorkload] = []string{metav1.NamespaceSystem, metav1.NamespacePublic}
	IgnoreCommandInNamespace[apis.TypeScanImages] = []string{}
}

func ignoreNamespace(command apis.NotificationPolicyType, namespace string) bool {
	InitIgnoreCommandInNamespace()
	if s, ok := IgnoreCommandInNamespace[command]; ok {
		for i := range s {
			if s[i] == namespace {
				return true
			}
		}
	}
	return false
}
func (mainHandler *MainHandler) listWorkloads(namespaces []string, resource string, labels, fields map[string]string) ([]k8sinterface.IWorkload, error) {
	groupVersionResource, err := k8sinterface.GetGroupVersionResource(resource)
	if err != nil {
		return nil, err
	}
	res := make([]k8sinterface.IWorkload, 0, 1)
	for nsIdx := range namespaces {
		iwls, err := mainHandler.k8sAPI.ListWorkloads(&groupVersionResource, namespaces[nsIdx], labels, fields)
		if err != nil {
			return res, err
		}
		res = append(res, iwls...)
	}
	return res, nil
}
func (mainHandler *MainHandler) getResourcesIDs(workloads []k8sinterface.IWorkload) ([]string, []error) {
	errs := []error{}
	idMap := make(map[string]interface{})
	for i := range workloads {
		switch workloads[i].GetKind() {
		case "Namespace":
			idMap[pkgwlid.GetWLID(utils.ClusterConfig.ClusterName, workloads[i].GetName(), "namespace", workloads[i].GetName())] = true
		default:
			if wlid := workloads[i].GetWlid(); wlid != "" {
				idMap[wlid] = true
			} else {
				// find wlid
				kind, name, err := mainHandler.k8sAPI.CalculateWorkloadParentRecursive(workloads[i])
				if err != nil {
					errs = append(errs, fmt.Errorf("CalculateWorkloadParentRecursive: namespace: %s, pod name: %s, error: %s", workloads[i].GetNamespace(), workloads[i].GetName(), err.Error()))
				}
				wlid := pkgwlid.GetWLID(utils.ClusterConfig.ClusterName, workloads[i].GetNamespace(), kind, name)
				if wlid != "" {
					idMap[wlid] = true
				}
			}
		}
	}
	return utils.MapToString(idMap), errs
}

func getCommandNamespace(command *apis.Command) string {
	if command.Wlid != "" {
		return pkgwlid.GetNamespaceFromWlid(command.Wlid)
	}
	if command.WildWlid != "" {
		return pkgwlid.GetNamespaceFromWlid(command.WildWlid)
	}
	return ""
}

func getCommandID(command *apis.Command) string {
	if command.Wlid != "" {
		return command.Wlid
	}
	if command.WildWlid != "" {
		return command.WildWlid
	}
	return ""
}

func resourceList(command apis.NotificationPolicyType) []string {
	switch command {
	case apis.TypeClusterUnregistered:
		return []string{"namespaces", "pods"}
	case apis.TypeDecryptSecret, apis.TypeEncryptSecret:
		return []string{"secrets"}
	default:
		return []string{"pods"}

	}

}

func notWaitAtAll() {
}

func isActionNeedToWait(action apis.Command) waitFunc {
	if f, ok := actionNeedToBeWaitOnStartUp[action.CommandName]; ok {
		return f
	}
	return notWaitAtAll
}

func waitForVulnScanReady() {
	fullURL := getVulnScanURL()
	// replace port
	fullURL.Host = strings.ReplaceAll(fullURL.Host, fullURL.Port(), probes.ReadinessPort)
	// replace path
	fullURL.Path = fmt.Sprintf("v1/%s", probes.ReadinessPath)

	timer := time.NewTimer(time.Duration(1) * time.Minute)

	for {
		timer.Reset(time.Duration(1) * time.Second)
		<-timer.C
		req, err := http.NewRequest(http.MethodHead, fullURL.String(), nil)
		if err != nil {
			glog.Warningf("failed to create http req with err %s", err.Error())
			continue
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			glog.Infof("return response with err %s", err.Error())
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 203 {
			glog.Info("vuln scan is ready")
			break
		}

	}
}

func waitForKubescapeReady() {
	fullURL := getKubescapeV1ScanURL()
	fullURL.Path = "readyz"
	timer := time.NewTimer(time.Duration(1) * time.Minute)

	for {
		timer.Reset(time.Duration(1) * time.Second)
		<-timer.C
		req, err := http.NewRequest(http.MethodHead, fullURL.String(), nil)
		if err != nil {
			glog.Warningf("failed to create http req with err %s", err.Error())
			continue
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			glog.Infof("return response with err %s", err.Error())
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 203 {
			glog.Info("kubescape service is ready")
			break
		}

	}
}
