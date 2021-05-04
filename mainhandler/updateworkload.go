package mainhandler

import (
	"context"
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/k8sworkloads"
	"strings"
	"time"

	"github.com/armosec/capacketsgo/apis"
	"github.com/armosec/capacketsgo/k8sinterface"
	reporterlib "github.com/armosec/capacketsgo/system-reports/datastructures"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"

	// corev1beta1 "k8s.io/api/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (actionHandler *ActionHandler) update(command string) error {
	kind := cautils.GetKindFromWlid(actionHandler.wlid)
	workload, err := actionHandler.k8sAPI.GetWorkloadByWlid(actionHandler.wlid)
	if err != nil {
		return err
	}
	actionHandler.editWorkload(workload, command)

	switch kind {
	case "Pod":
		return actionHandler.updatePod(workload)
	default:
		return actionHandler.updateWorkload(workload)
	}
}

func (actionHandler *ActionHandler) updateWorkload(workload *k8sinterface.Workload) error {
	_, err := actionHandler.k8sAPI.UpdateWorkload(workload)
	if persistentVolumeFound(workload) {
		return actionHandler.deletePods(workload)
	}
	return err
}

func (actionHandler *ActionHandler) updatePod(workload *k8sinterface.Workload) error {
	if err := actionHandler.k8sAPI.DeleteWorkloadByWlid(actionHandler.wlid); err == nil {
		workload.RemovePodStatus()
		workload.RemoveResourceVersion()
		for {
			_, err = actionHandler.k8sAPI.GetWorkloadByWlid(actionHandler.wlid)
			if err != nil {
				break
			}
			time.Sleep(time.Second * 1)
		}
		actionHandler.k8sAPI.CreateWorkload(workload)
	}
	return nil
}

func (actionHandler *ActionHandler) editWorkload(workload *k8sinterface.Workload, command string) {
	switch command {
	case apis.UPDATE:
		workload.SetInject()
		workload.SetWlid(actionHandler.wlid)
		workload.SetUpdateTime()
	case apis.REMOVE:
		workload.RemoveInject()
		workload.RemoveWlid()
		workload.RemoveUpdateTime()
	}
}
func (actionHandler *ActionHandler) deletePods(workload *k8sinterface.Workload) error {
	selector, err := workload.GetSelector()
	if err != nil || selector == nil {

	}
	lisOptions := metav1.ListOptions{
		LabelSelector: labels.Set(selector.MatchLabels).AsSelector().String(),
	}
	return actionHandler.k8sAPI.KubernetesClient.CoreV1().Pods(cautils.GetNamespaceFromWlid(actionHandler.wlid)).DeleteCollection(context.Background(), metav1.DeleteOptions{}, lisOptions)
}

func persistentVolumeFound(workload *k8sinterface.Workload) bool {
	volumes, _ := workload.GetVolumes()
	for _, vol := range volumes {
		if vol.PersistentVolumeClaim != nil && vol.PersistentVolumeClaim.ClaimName != "" {
			return true
		}
	}
	return false
}

// func updateWorkload(wlid string, command string, cmd *cautils.Command) error {
// 	var err error
// 	namespace := cautils.GetNamespaceFromWlid(wlid)
// 	kind := cautils.GetKindFromWlid(wlid)

// 	workload, err := getWorkload(wlid)
// 	if err != nil {
// 		return err
// 	}
// 	ctx := context.Background()
// 	switch kind {
// 	case "Namespace":
// 		w := workload.(*corev1.Namespace)
// 		injectNS(&w.ObjectMeta, command)
// 		_, err = k8sworkloads.KubernetesClient.CoreV1().Namespaces().Update(ctx, w, metav1.UpdateOptions{})

// 	case "Deployment":
// 		w := workload.(*appsv1.Deployment)
// 		workloadUpdate(&w.ObjectMeta, command, wlid)
// 		inject(&w.ObjectMeta, &w.Spec.Template, command, wlid, cmd)
// 		_, err = k8sworkloads.KubernetesClient.AppsV1().Deployments(namespace).Update(ctx, w, metav1.UpdateOptions{})

// 	case "ReplicaSet":
// 		w := workload.(*appsv1.ReplicaSet)
// 		workloadUpdate(&w.ObjectMeta, command, wlid)
// 		inject(&w.ObjectMeta, &w.Spec.Template, command, wlid, cmd)
// 		_, err = k8sworkloads.KubernetesClient.AppsV1().ReplicaSets(namespace).Update(ctx, w, metav1.UpdateOptions{})

// 	case "DaemonSet":
// 		w := workload.(*appsv1.DaemonSet)
// 		workloadUpdate(&w.ObjectMeta, command, wlid)
// 		inject(&w.ObjectMeta, &w.Spec.Template, command, wlid, cmd)
// 		_, err = k8sworkloads.KubernetesClient.AppsV1().DaemonSets(namespace).Update(ctx, w, metav1.UpdateOptions{})

// 	case "StatefulSet":
// 		w := workload.(*appsv1.StatefulSet)
// 		workloadUpdate(&w.ObjectMeta, command, wlid)
// 		inject(&w.ObjectMeta, &w.Spec.Template, command, wlid, cmd)
// 		w, err = k8sworkloads.KubernetesClient.AppsV1().StatefulSets(namespace).Update(ctx, w, metav1.UpdateOptions{})

// 	case "PodTemplate":
// 		w := workload.(*corev1.PodTemplate)
// 		workloadUpdate(&w.ObjectMeta, command, wlid)
// 		inject(&w.ObjectMeta, &w.Template, command, wlid, cmd)
// 		_, err = k8sworkloads.KubernetesClient.CoreV1().PodTemplates(namespace).Update(ctx, w, metav1.UpdateOptions{})
// 	case "CronJob":
// 		w := workload.(*v1beta1.CronJob)
// 		workloadUpdate(&w.ObjectMeta, command, wlid)
// 		inject(&w.ObjectMeta, &w.Spec.JobTemplate.Spec.Template, command, wlid, cmd)
// 		_, err = k8sworkloads.KubernetesClient.BatchV1beta1().CronJobs(namespace).Update(ctx, w, metav1.UpdateOptions{})

// 	case "Job":
// 		err = fmt.Errorf("")
// 		// Do nothing
// 		// w := workload.(*batchv1.Job)
// 		// inject(&w.Spec.Template, command, wlid)
// 		// cleanSelector(w.Spec.Selector)
// 		// err = clientset.BatchV1().Jobs(namespace).Delete(w.Name, &v1.DeleteOptions{})
// 		// if err == nil {
// 		// 	w.Status = batchv1.JobStatus{}
// 		// 	w.ObjectMeta.ResourceVersion = ""
// 		// 	for {
// 		// 		_, err = clientset.BatchV1().Jobs(namespace).Get(w.Name, v1.GetOptions{})
// 		// 		if err != nil {
// 		// 			break
// 		// 		}
// 		// 		time.Sleep(time.Second * 1)
// 		// 	}
// 		// 	w, err = clientset.BatchV1().Jobs(namespace).Create(w)
// 		// }

// 	case "Pod":
// 		w := workload.(*corev1.Pod)
// 		injectPod(&w.ObjectMeta, &w.Spec, command, wlid)
// 		err = k8sworkloads.KubernetesClient.CoreV1().Pods(namespace).Delete(ctx, w.Name, metav1.DeleteOptions{})
// 		if err == nil {
// 			w.Status = corev1.PodStatus{}
// 			w.ObjectMeta.ResourceVersion = ""
// 			for {
// 				_, err = k8sworkloads.KubernetesClient.CoreV1().Pods(namespace).Get(ctx, w.Name, metav1.GetOptions{})
// 				if err != nil {
// 					break
// 				}
// 				time.Sleep(time.Second * 1)
// 			}
// 			_, err = k8sworkloads.KubernetesClient.CoreV1().Pods(namespace).Create(ctx, w, metav1.CreateOptions{})
// 		}
// 	default:
// 		err = fmt.Errorf("command %s not supported with kind: %s", command, cautils.GetKindFromWlid(wlid))
// 	}
// 	return err

// }

func inject(objectMeta *metav1.ObjectMeta, template *corev1.PodTemplateSpec, command, wlid string, cmd *cautils.Command) {
	jobsAnnot := reporterlib.JobsAnnotations{}
	var annot []byte
	if jobid, hasJobID := cmd.Args["jobID"]; hasJobID {
		jobsAnnot.CurrJobID = fmt.Sprintf("%v", jobid)
		jobsAnnot.LastActionID = "3"

		annot, _ = json.Marshal(jobsAnnot)

	}
	switch command {
	case apis.UPDATE:
		injectWlid(&template.ObjectMeta.Annotations, wlid)
		injectTime(&template.ObjectMeta.Annotations)
		injectLabel(&template.ObjectMeta.Labels)
		if len(jobsAnnot.CurrJobID) > 0 {
			template.ObjectMeta.Annotations[reporterlib.CAJobs] = string(annot)
		}
		removeAnnotation(&template.ObjectMeta, CAIgnoe)
		removeAnnotation(objectMeta, CAIgnoe)

	case apis.RESTART:
		injectTime(&template.ObjectMeta.Annotations)
	case apis.REMOVE:
		restoreConatinerCommand(&template.Spec)
		removeCASpec(&template.Spec)
		removeCAMetadata(&template.ObjectMeta)
		injectAnnotation(&template.ObjectMeta.Annotations, CAIgnoe, "true")
		injectAnnotation(&objectMeta.Annotations, CAIgnoe, "true")
	}
}

func workloadUpdate(objectMeta *metav1.ObjectMeta, command, wlid string) {
	switch command {
	case apis.REMOVE:
		removeCAMetadata(objectMeta)
	}
}

func injectPod(metadata *metav1.ObjectMeta, spec *corev1.PodSpec, command, wlid string) {
	switch command {
	case apis.UPDATE:
		injectWlid(&metadata.Annotations, wlid)
		injectTime(&metadata.Annotations)
		injectAnnotation(&(metadata.Annotations), reporterlib.CAJobs, wlid)
		injectLabel(&metadata.Labels)
		removeAnnotation(metadata, CAIgnoe)
	case apis.SIGN:
		updateLabel(&metadata.Labels)
		injectTime(&metadata.Annotations)
	case apis.RESTART:
		injectTime(&metadata.Annotations)
	case apis.REMOVE:
		restoreConatinerCommand(spec)
		removeCASpec(spec)
		removeCAMetadata(metadata)
		injectAnnotation(&metadata.Annotations, CAIgnoe, "true")

	}
}

func injectNS(metadata *metav1.ObjectMeta, command string) {
	switch command {
	case apis.INJECT:
		injectTime(&metadata.Annotations)
		injectLabel(&metadata.Labels)

	case apis.REMOVE:
		removeCAMetadata(metadata)
	}
}
func restoreConatinerCommand(spec *corev1.PodSpec) {
	cmdEnv := "CAA_OVERRIDDEN_CMD"
	argsEnv := "CAA_OVERRIDDEN_ARGS"
	for con := range spec.Containers {
		for env := range spec.Containers[con].Env {
			if spec.Containers[con].Env[env].Name == cmdEnv {
				cmdVal := spec.Containers[con].Env[env].Value
				if cmdVal == "nil" {
					glog.Errorf("invalid env value. conatiner: %s, env: %s=%s. current container command: %v, current container args: %v", spec.Containers[con].Name, cmdEnv, cmdVal, spec.Containers[con].Command, spec.Containers[con].Args)
					continue
				}
				newCMD := []string{}
				json.Unmarshal([]byte(cmdVal), &newCMD)
				spec.Containers[con].Command = newCMD
			}
			if spec.Containers[con].Env[env].Name == argsEnv {
				argsVal := spec.Containers[con].Env[env].Value
				if argsVal == "nil" {
					glog.Errorf("invalid env value. conatiner: %s, env: %s=%s. current container command: %v, current container args: %v", spec.Containers[con].Name, argsEnv, argsVal, spec.Containers[con].Command, spec.Containers[con].Args)
					continue
				}
				newArgs := []string{}
				json.Unmarshal([]byte(argsVal), &newArgs)
				spec.Containers[con].Args = newArgs
			}
		}
	}
}
func removeCASpec(spec *corev1.PodSpec) {
	// remove init container
	nOfContainers := len(spec.InitContainers)
	for i := 0; i < nOfContainers; i++ {
		if spec.InitContainers[i].Name == cautils.CAInitContainerName {
			if nOfContainers < 2 { //i is the only element in the slice so we need to remove this entry from the map
				spec.InitContainers = []corev1.Container{}
			} else if i == nOfContainers-1 { // i is the last element in the slice so i+1 is out of range
				spec.InitContainers = spec.InitContainers[:i]
			} else {
				spec.InitContainers = append(spec.InitContainers[:i], spec.InitContainers[i+1:]...)
			}
			nOfContainers--
			i--
		}
	}

	// remove volumes
	for injected := range cautils.InjectedVolumes {
		removeVolumes(&spec.Volumes, cautils.InjectedVolumes[injected])
	}

	// remove environment varibles
	for i := range spec.Containers {
		for injectedEnvs := range cautils.InjectedEnvironments {
			removeEnvironmentVariable(&spec.Containers[i].Env, cautils.InjectedEnvironments[injectedEnvs])
		}
	}

	// remove volumeMounts
	for i := range spec.Containers {
		for injected := range cautils.InjectedVolumeMounts {
			removeVolumeMounts(&spec.Containers[i].VolumeMounts, cautils.InjectedVolumeMounts[injected])
		}
	}
}

func removeEnvironmentVariable(envs *[]corev1.EnvVar, env string) {
	nOfEnvs := len(*envs)
	for i := 0; i < nOfEnvs; i++ {
		if (*envs)[i].Name == env {
			if nOfEnvs < 2 { //i is the only element in the slice so we need to remove this entry from the map
				*envs = []corev1.EnvVar{}
			} else if i == nOfEnvs-1 { // i is the last element in the slice so i+1 is out of range
				*envs = (*envs)[:i]
			} else {
				*envs = append((*envs)[:i], (*envs)[i+1:]...)
			}
			nOfEnvs--
			i--
		}
	}
}

func removeVolumes(volumes *[]corev1.Volume, vol string) {
	nOfvolumes := len(*volumes)
	for i := 0; i < nOfvolumes; i++ {
		if (*volumes)[i].Name == vol {
			if nOfvolumes < 2 { //i is the only element in the slice so we need to remove this entry from the map
				*volumes = []corev1.Volume{}
			} else if i == nOfvolumes-1 { // i is the last element in the slice so i+1 is out of range
				*volumes = (*volumes)[:i]
			} else {
				*volumes = append((*volumes)[:i], (*volumes)[i+1:]...)
			}
			nOfvolumes--
			i--
		}
	}
}

func removeVolumeMounts(volumes *[]corev1.VolumeMount, vol string) {
	nOfvolumes := len(*volumes)
	for i := 0; i < nOfvolumes; i++ {
		if (*volumes)[i].Name == vol {
			if nOfvolumes < 2 { //i is the only element in the slice so we need to remove this entry from the map
				*volumes = []corev1.VolumeMount{}
			} else if i == nOfvolumes-1 { // i is the last element in the slice so i+1 is out of range
				*volumes = (*volumes)[:i]
			} else {
				*volumes = append((*volumes)[:i], (*volumes)[i+1:]...)
			}
			nOfvolumes--
			i--
		}
	}
}

func injectAnnotation(annotations *map[string]string, key, val string) {
	if *annotations == nil {
		(*annotations) = make(map[string]string)
	}
	(*annotations)[key] = val
}

func removeAnnotation(meatdata *metav1.ObjectMeta, key string) {
	if meatdata.Annotations != nil {
		delete(meatdata.Annotations, key)
	}
}
func removeLabel(meatdata *metav1.ObjectMeta, key string) {
	if meatdata.Labels != nil {
		delete(meatdata.Labels, key)
	}
}
func injectWlid(annotations *map[string]string, wlid string) {
	injectAnnotation(annotations, CAWlidOld, wlid)
	injectAnnotation(annotations, CAWlid, wlid)
}

func injectTime(annotations *map[string]string) {
	injectAnnotation(annotations, CAUpdate, string(time.Now().UTC().Format("02-01-2006 15:04:05")))
}

func updateLabel(labels *map[string]string) {
	if *labels == nil {
		(*labels) = make(map[string]string)
	}
	(*labels)[CALabel] = "signed"
}

func injectLabel(labels *map[string]string) {
	if *labels == nil {
		(*labels) = make(map[string]string)
	}
	(*labels)[CAInject] = "add"
	(*labels)[CAInjectOld] = "add" // DEPRECATED
}

func removeCAMetadata(meatdata *metav1.ObjectMeta) {
	if meatdata.Labels != nil {
		delete(meatdata.Labels, CAInject)
		delete(meatdata.Labels, CAInjectOld) // DEPRECATED
		delete(meatdata.Labels, CALabel)
	}
	if meatdata.Annotations != nil {
		delete(meatdata.Annotations, CAWlidOld) // DEPRECATED
		delete(meatdata.Annotations, CAStatus)
		delete(meatdata.Annotations, CASigned)
		delete(meatdata.Annotations, CAWlid)
		delete(meatdata.Annotations, CAAttached)
		delete(meatdata.Annotations, CAUpdate)
		delete(meatdata.Annotations, CAJobs)
	}
}

func cleanSelector(selector *metav1.LabelSelector) {
	if len(selector.MatchLabels) == 0 && len(selector.MatchLabels) == 0 {
		selector = &metav1.LabelSelector{}
	}
}

// excludeWlid - add a wlid to the ignore list
func excludeWlid(nsWlid, workloadWlid string) error {
	ctx := context.Background()
	workload, err := getWorkload(nsWlid)
	if err != nil {
		return err
	}
	w := workload.(*corev1.Namespace)
	// if inject lable not in namespace than ignore namespace
	if !isInjectLableFound(w.Labels) {
		return nil
	}
	injectList := workloadWlid
	if w.Annotations != nil {
		if ignoreList, ok := w.Annotations[CAIgnoe]; ok && ignoreList != "" {
			// wlids := strings.Split(ignoreList, ";")
			injectList = fmt.Sprintf("%s;%s", ignoreList, workloadWlid)
		}
	}
	injectAnnotation(&w.Annotations, CAIgnoe, injectList)
	_, err = k8sworkloads.KubernetesClient.CoreV1().Namespaces().Update(ctx, w, metav1.UpdateOptions{})
	return err
}

// excludeWlid - remove a wlid from the ignore list
func includeWlid(nsWlid, workloadWlid string) error {
	ctx := context.Background()
	workload, err := getWorkload(nsWlid)
	if err != nil {
		return err
	}
	w := workload.(*corev1.Namespace)

	// if inject lable not in namespace than ignore namespace
	if !isInjectLableFound(w.Labels) {
		return nil
	}

	// if there are no annotations so there is nothing to remove
	if w.Annotations == nil {
		return nil
	}
	ignoreList, ok := w.Annotations[CAIgnoe]
	if !ok || ignoreList == "" {
		return nil
	}

	injectList := ""
	wlids := strings.Split(ignoreList, ";")
	for i := range wlids {
		if wlids[i] != workloadWlid {
			injectList += wlids[i] + ";"
		}
	}
	injectAnnotation(&w.Annotations, CAIgnoe, injectList)
	_, err = k8sworkloads.KubernetesClient.CoreV1().Namespaces().Update(ctx, w, metav1.UpdateOptions{})
	return err
}

func isInjectLableFound(labels map[string]string) bool {
	if labels == nil {
		return false
	}
	if _, ok := labels[CAInject]; ok {
		return true
	}
	if _, ok := labels[CAInjectOld]; ok {
		return true
	}
	return false
}

// CreateSecret create secret in k8s
func CreateSecret(secret *corev1.Secret) error {
	ctx := context.Background()
	_, err := k8sworkloads.KubernetesClient.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	return err
}

// UpdateSecret create secret in k8s
func UpdateSecret(secret *corev1.Secret, command string) error {
	ctx := context.Background()
	secretUpdate(&secret.ObjectMeta, command)
	_, err := k8sworkloads.KubernetesClient.CoreV1().Secrets(secret.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

// DeleteSecret delete secret from k8s
func DeleteSecret(namespace, secretName string) error {
	ctx := context.Background()
	err := k8sworkloads.KubernetesClient.CoreV1().Secrets(namespace).Delete(ctx, secretName, metav1.DeleteOptions{})
	return err
}

// GetSecret get secret from k8s
func GetSecret(namespace, secretName string) (*corev1.Secret, error) {
	ctx := context.Background()
	return k8sworkloads.KubernetesClient.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
}

// ListSecrets list secret from k8s
func ListSecrets(namespace string, labelSelector map[string]string) (*corev1.SecretList, error) {
	ctx := context.Background()

	listOptions := metav1.ListOptions{}
	if labelSelector != nil {
		set := labels.Set(labelSelector)
		listOptions.LabelSelector = set.AsSelector().String()
	}
	return k8sworkloads.KubernetesClient.CoreV1().Secrets(namespace).List(ctx, listOptions)
}

func secretUpdate(objectMeta *metav1.ObjectMeta, command string) {
	switch command {
	case apis.DECRYPT:
		removeLabel(objectMeta, CAInject)
		removeLabel(objectMeta, CAInjectOld) // DEPRECATED
		injectAnnotation(&objectMeta.Annotations, CAIgnoe, "true")
	case apis.ENCRYPT:
		removeAnnotation(objectMeta, CAIgnoe)
	}
}
