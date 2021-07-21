package mainhandler

import (
	"context"
	"fmt"
	"k8s-ca-websocket/cautils"
	"time"

	"github.com/armosec/capacketsgo/apis"
	pkgcautils "github.com/armosec/capacketsgo/cautils"
	"github.com/armosec/capacketsgo/k8sinterface"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"

	// corev1beta1 "k8s.io/api/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (actionHandler *ActionHandler) update(command string) error {
	workload, err := actionHandler.k8sAPI.GetWorkloadByWlid(actionHandler.wlid)
	if err != nil {
		glog.Error(err)
		return err
	}

	if err := actionHandler.editWorkload(workload, command); err != nil {
		glog.Warningf("%s, wlid: '%s'", err.Error(), actionHandler.wlid)
		return nil
	}

	glog.Infof("Command: %s, Updated workload: %s", actionHandler.command.CommandName, workload.Json())

	switch cautils.GetKindFromWlid(actionHandler.wlid) {
	case "Pod":
		glog.Infof("updating pod: '%s'", workload.GetName())
		return actionHandler.updatePod(workload)
	default:
		glog.Infof("updating workload: '%s'", workload.GetName())
		return actionHandler.updateWorkload(workload)
	}
}
func (actionHandler *ActionHandler) updateWorkload(workload *k8sinterface.Workload) error {
	deletePods := isForceDelete(actionHandler.command.Args)

	if persistentVolumeFound(workload) {
		deletePods = true
	}

	if deletePods {
		glog.Infof("Updating workload by deleting pods, workloadID: %s", actionHandler.wlid)
		return actionHandler.deletePods(workload)
	}
	_, err := actionHandler.k8sAPI.UpdateWorkload(workload)
	return err
}

func (actionHandler *ActionHandler) updatePod(workload *k8sinterface.Workload) error {
	glog.Infof("in updatePod")
	var err error
	maxTime := float64(360) // wait for 3 minutes
	timer := float64(0)
	sleepTime := time.Second * 1

	if err = actionHandler.k8sAPI.DeleteWorkloadByWlid(actionHandler.wlid); err == nil {
		workload.RemovePodStatus()
		workload.RemoveResourceVersion()
		for {
			_, err = actionHandler.k8sAPI.GetWorkloadByWlid(actionHandler.wlid)
			if err != nil {
				glog.Error(err)
				break
			}
			if maxTime <= timer {
				return fmt.Errorf("Failed to restart pod, time: %v seconds, workloadID: %s", maxTime, actionHandler.wlid)
			}
			time.Sleep(sleepTime)
			timer += sleepTime.Seconds()

		}
		_, err = actionHandler.k8sAPI.CreateWorkload(workload)
	}
	return err
}

func (actionHandler *ActionHandler) editWorkload(workload *k8sinterface.Workload, command string) error {
	jobTracking := cautils.NewJobTracking(actionHandler.reporter)

	switch command {
	case apis.UPDATE, apis.ATTACH:
		if workload.IsAttached() {
			return fmt.Errorf("workload already attached")
		}
		if workload.IsIncompatible() {
			return fmt.Errorf("workload reported incompatible")
		}
		workload.SetJobID(*jobTracking)
		workload.SetInject()
		workload.SetWlid(actionHandler.wlid)
		workload.SetUpdateTime()
	case apis.RESTART:
		workload.SetUpdateTime()
		workload.SetJobID(*jobTracking)
	case apis.INJECT:
		workload.SetInject()
		workload.SetJobID(*jobTracking)
	case apis.REMOVE, apis.DETACH:
		workload.RemoveInject() // DEPRECATED
		workload.SetIgnore()
		workload.RemoveWlid()
		workload.RemoveUpdateTime()
		workload.RemoveJobID()
	case apis.INCOMPATIBLE:
		workload.SetIgnore()
		workload.SetIncompatible()
	case apis.UNREGISTERED:
		workload.RemoveInject()     // NS/WL DEPRECATED
		workload.RemoveIgnore()     // NS/WL DEPRECATED
		workload.RemoveWlid()       // WL
		workload.RemoveUpdateTime() // WL
		workload.RemoveJobID()      // NS/WL
		workload.RemoveCompatible() // WL
	}
	return nil
}
func (actionHandler *ActionHandler) deletePods(workload *k8sinterface.Workload) error {
	lisOptions := metav1.ListOptions{}

	selector, err := workload.GetSelector()
	if err == nil && selector != nil {
		lisOptions.LabelSelector = labels.Set(selector.MatchLabels).AsSelector().String()
	}

	return actionHandler.k8sAPI.KubernetesClient.CoreV1().Pods(cautils.GetNamespaceFromWlid(actionHandler.wlid)).DeleteCollection(context.Background(), metav1.DeleteOptions{}, lisOptions)
}

func injectLabel(objectMeta *metav1.ObjectMeta, key, val string) {
	if objectMeta.Labels == nil {
		objectMeta.Labels = make(map[string]string)
	}
	objectMeta.Labels[key] = val
}

func removeAnnotation(meatdata *metav1.ObjectMeta, key string) {
	if meatdata.Annotations != nil {
		delete(meatdata.Annotations, key)
	}
}

// UpdateSecret create secret in k8s
func (actionHandler *ActionHandler) UpdateSecret(secret *corev1.Secret, command string) error {
	secretUpdate(&secret.ObjectMeta, command)
	_, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().Secrets(secret.Namespace).Update(actionHandler.k8sAPI.Context, secret, metav1.UpdateOptions{})
	return err
}

// DeleteSecret delete secret from k8s
func (actionHandler *ActionHandler) DeleteSecret(namespace, secretName string) error {
	ctx := context.Background()
	err := actionHandler.k8sAPI.KubernetesClient.CoreV1().Secrets(namespace).Delete(ctx, secretName, metav1.DeleteOptions{})
	return err
}

// GetSecret get secret from k8s
func (actionHandler *ActionHandler) GetSecret(namespace, secretName string) (*corev1.Secret, error) {
	return actionHandler.k8sAPI.KubernetesClient.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
}

// ListSecrets list secret from k8s
func (actionHandler *ActionHandler) ListSecrets(namespace string, labelSelector map[string]string) (*corev1.SecretList, error) {
	ctx := context.Background()

	listOptions := metav1.ListOptions{}
	if labelSelector != nil {
		set := labels.Set(labelSelector)
		listOptions.LabelSelector = set.AsSelector().String()
	}
	return actionHandler.k8sAPI.KubernetesClient.CoreV1().Secrets(namespace).List(ctx, listOptions)
}
func removeLabel(meatdata *metav1.ObjectMeta, key string) {
	if meatdata.Labels != nil {
		delete(meatdata.Labels, key)
	}
}
func secretUpdate(objectMeta *metav1.ObjectMeta, command string) {
	switch command {
	case apis.DECRYPT:
		// removeLabel(objectMeta, pkgcautils.ArmoInitialSecret)
		injectLabel(objectMeta, pkgcautils.ArmoSecretStatus, pkgcautils.ArmoSecretClearStatus)
	// 	removeLabel(objectMeta, pkgcautils.CAInitialSecret)     // DEPRECATED
	// 	removeLabel(objectMeta, pkgcautisls.CAProtectedSecret)   // DEPRECATED
	// 	injectLabel(objectMeta, pkgcautils.ArmoAttach, "false") // DEPRECATED
	case apis.ENCRYPT:
		// injectLabel(objectMeta.Labels, pkgcautils.ArmoAttach, "true")
		removeAnnotation(objectMeta, "kubectl.kubernetes.io/last-applied-configuration")
		injectLabel(objectMeta, pkgcautils.ArmoSecretStatus, pkgcautils.ArmoSecretProtectStatus)
	case apis.UNREGISTERED:
		removeLabel(objectMeta, pkgcautils.ArmoInitialSecret)
		removeLabel(objectMeta, pkgcautils.ArmoSecretStatus)
		removeLabel(objectMeta, pkgcautils.CAInitialSecret)   // DEPRECATED
		removeLabel(objectMeta, pkgcautils.CAProtectedSecret) // DEPRECATED
		removeLabel(objectMeta, pkgcautils.ArmoAttach)        // DEPRECATED
	}
}
