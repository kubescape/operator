package mainhandler

import (
	"fmt"
	"k8s-ca-websocket/cautils"
	"strings"

	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/armosec/armoapi-go/apis"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/utils-k8s-go/secrethandling"
)

var IgnoreCommandInNamespace = map[string][]string{}

func InitIgnoreCommandInNamespace() {
	if len(IgnoreCommandInNamespace) != 0 {
		return
	}
	IgnoreCommandInNamespace[apis.UPDATE] = []string{metav1.NamespaceSystem, metav1.NamespacePublic, cautils.CA_NAMESPACE}
	IgnoreCommandInNamespace[apis.INJECT] = []string{metav1.NamespaceSystem, metav1.NamespacePublic, cautils.CA_NAMESPACE}
	IgnoreCommandInNamespace[apis.DECRYPT] = []string{metav1.NamespaceSystem, metav1.NamespacePublic, cautils.CA_NAMESPACE}
	IgnoreCommandInNamespace[apis.ENCRYPT] = []string{metav1.NamespaceSystem, metav1.NamespacePublic, cautils.CA_NAMESPACE}
	IgnoreCommandInNamespace[apis.REMOVE] = []string{metav1.NamespaceSystem, metav1.NamespacePublic, cautils.CA_NAMESPACE}
	IgnoreCommandInNamespace[apis.RESTART] = []string{metav1.NamespaceSystem, metav1.NamespacePublic}
	IgnoreCommandInNamespace[apis.SCAN] = []string{}
	// apis.SCAN:    {metav1.NamespaceSystem, metav1.NamespacePublic, cautils.CA_NAMESPACE},
}

func ignoreNamespace(command, namespace string) bool {
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
func (mainHandler *MainHandler) listWorkloads(namespace, resource string, labels, fields map[string]string) ([]k8sinterface.IWorkload, error) {
	groupVersionResource, err := k8sinterface.GetGroupVersionResource(resource)
	if err != nil {
		return nil, err
	}
	return mainHandler.k8sAPI.ListWorkloads(&groupVersionResource, namespace, labels, fields)
}
func (mainHandler *MainHandler) GetResourcesIDs(workloads []k8sinterface.IWorkload) ([]string, []error) {
	errs := []error{}
	idMap := make(map[string]interface{})
	for i := range workloads {
		switch workloads[i].GetKind() {
		case "Namespace":
			idMap[pkgwlid.GetWLID(cautils.CA_CLUSTER_NAME, workloads[i].GetName(), "namespace", workloads[i].GetName())] = true
		case "Secret":
			secretName := strings.TrimPrefix(workloads[i].GetName(), secrethandling.ArmoShadowSecretPrefix) // remove shadow secret prefix
			idMap[secrethandling.GetSID(cautils.CA_CLUSTER_NAME, workloads[i].GetNamespace(), secretName, "")] = true
		default:
			if wlid := workloads[i].GetWlid(); wlid != "" {
				idMap[wlid] = true
			} else {
				// find wlid
				kind, name, err := mainHandler.k8sAPI.CalculateWorkloadParentRecursive(workloads[i])
				if err != nil {
					errs = append(errs, fmt.Errorf("CalculateWorkloadParentRecursive: namespace: %s, pod name: %s, error: %s", workloads[i].GetNamespace(), workloads[i].GetName(), err.Error()))
				}
				wlid := pkgwlid.GetWLID(cautils.CA_CLUSTER_NAME, workloads[i].GetNamespace(), kind, name)
				if wlid != "" {
					idMap[wlid] = true
				}
			}
		}
	}
	return cautils.MapToString(idMap), errs
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

func resourceList(command string) []string {
	switch command {
	case apis.UNREGISTERED:
		return []string{"namespaces", "pods"}
		// return []string{"namespaces", "secrets", "pods"}
	case apis.DECRYPT, apis.ENCRYPT:
		return []string{"secrets"}
	default:
		return []string{"pods"}

	}

}

func sidFallback(sessionObj *cautils.SessionObj) {
	if sessionObj.Command.GetID() == "" {
		sid, err := getSIDFromArgs(sessionObj.Command.Args)
		if err != nil || sid == "" {
			return
		}
		sessionObj.Command.Sid = sid
	}
}

func jobStatus(commandName string) string {
	if commandName == apis.UPDATE || commandName == apis.INJECT || commandName == apis.ATTACH || commandName == apis.RESTART {
		return reporterlib.JobSuccess
	}
	return reporterlib.JobDone
}
