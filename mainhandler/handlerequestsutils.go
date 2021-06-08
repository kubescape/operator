package mainhandler

import (
	"fmt"
	"k8s-ca-websocket/cautils"

	"github.com/armosec/capacketsgo/k8sinterface"
)

func (mainHandler *MainHandler) listWorkloads(namespace, resource string, labels map[string]string) ([]k8sinterface.Workload, error) {
	groupVersionResource, err := k8sinterface.GetGroupVersionResource(resource)
	if err != nil {
		return nil, err
	}
	return mainHandler.k8sAPI.ListWorkloads(&groupVersionResource, namespace, labels)
}
func (mainHandler *MainHandler) calculatePodsWlids(namespace string, pods []k8sinterface.Workload) ([]string, []error) {
	errs := []error{}
	wlidsMap := make(map[string]interface{})
	for i := range pods {
		if wlid := pods[i].GetWlid(); wlid != "" {
			wlidsMap[wlid] = true
		} else {
			// find wlid
			kind, name, err := mainHandler.k8sAPI.CalculateWorkloadParentRecursive(&pods[i])
			if err != nil {
				errs = append(errs, fmt.Errorf("CalculateWorkloadParentRecursive: namespace: %s, pod name: %s, error: %s", pods[i].GetNamespace(), pods[i].GetName(), err.Error()))
			}
			wlid := cautils.GetWLID(cautils.CA_CLUSTER_NAME, namespace, kind, name)
			if wlid != "" {
				wlidsMap[wlid] = true
			}
		}
	}
	return cautils.MapToString(wlidsMap), errs
}
