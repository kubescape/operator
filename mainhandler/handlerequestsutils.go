package mainhandler

import (
	"fmt"
	"strings"
	"time"

	"github.com/kubescape/operator/utils"

	"github.com/golang/glog"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-go/httputils"
	"github.com/armosec/utils-k8s-go/probes"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"

	"github.com/kubescape/k8s-interface/k8sinterface"
)

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
	return utils.MapToString(idMap), errs
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
		resp, err := httputils.HttpHead(VulnScanHttpClient, fullURL.String(), nil)
		if err != nil {
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
		resp, err := httputils.HttpHead(KubescapeHttpClient, fullURL.String(), nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 203 {
			glog.Info("kubescape service is ready")
			break
		}

	}
}
