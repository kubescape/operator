package websocket

import (
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/k8sworkloads"
	"strings"
	"time"

	reporterlib "asterix.cyberarmor.io/cyberarmor/capacketsgo/system-reports/datastructures"

	"github.com/golang/glog"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"

	// corev1beta1 "k8s.io/api/core/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func updateWorkload(wlid string, command string, cmd *cautils.Command) error {
	var err error
	namespace := cautils.GetNamespaceFromWlid(wlid)
	kind := cautils.GetKindFromWlid(wlid)

	workload, err := getWorkload(wlid)
	if err != nil {
		return err
	}

	switch kind {
	case "Namespace":
		w := workload.(*corev1.Namespace)
		injectNS(&w.ObjectMeta, command)
		_, err = k8sworkloads.KubernetesClient.CoreV1().Namespaces().Update(w)

	case "Deployment":
		w := workload.(*appsv1.Deployment)
		workloadUpdate(&w.ObjectMeta, command, wlid)
		inject(&w.ObjectMeta, &w.Spec.Template, command, wlid, cmd)
		_, err = k8sworkloads.KubernetesClient.AppsV1().Deployments(namespace).Update(w)

	case "ReplicaSet":
		w := workload.(*appsv1.ReplicaSet)
		workloadUpdate(&w.ObjectMeta, command, wlid)
		inject(&w.ObjectMeta, &w.Spec.Template, command, wlid, cmd)
		_, err = k8sworkloads.KubernetesClient.AppsV1().ReplicaSets(namespace).Update(w)

	case "DaemonSet":
		w := workload.(*appsv1.DaemonSet)
		workloadUpdate(&w.ObjectMeta, command, wlid)
		inject(&w.ObjectMeta, &w.Spec.Template, command, wlid, cmd)
		_, err = k8sworkloads.KubernetesClient.AppsV1().DaemonSets(namespace).Update(w)

	case "StatefulSet":
		w := workload.(*appsv1.StatefulSet)
		workloadUpdate(&w.ObjectMeta, command, wlid)
		inject(&w.ObjectMeta, &w.Spec.Template, command, wlid, cmd)
		w, err = k8sworkloads.KubernetesClient.AppsV1().StatefulSets(namespace).Update(w)

	case "PodTemplate":
		w := workload.(*corev1.PodTemplate)
		workloadUpdate(&w.ObjectMeta, command, wlid)
		inject(&w.ObjectMeta, &w.Template, command, wlid, cmd)
		_, err = k8sworkloads.KubernetesClient.CoreV1().PodTemplates(namespace).Update(w)
	case "CronJob":
		w := workload.(*v1beta1.CronJob)
		workloadUpdate(&w.ObjectMeta, command, wlid)
		inject(&w.ObjectMeta, &w.Spec.JobTemplate.Spec.Template, command, wlid, cmd)
		_, err = k8sworkloads.KubernetesClient.BatchV1beta1().CronJobs(namespace).Update(w)

	case "Job":
		err = fmt.Errorf("")
		// Do nothing
		// w := workload.(*batchv1.Job)
		// inject(&w.Spec.Template, command, wlid)
		// cleanSelector(w.Spec.Selector)
		// err = clientset.BatchV1().Jobs(namespace).Delete(w.Name, &v1.DeleteOptions{})
		// if err == nil {
		// 	w.Status = batchv1.JobStatus{}
		// 	w.ObjectMeta.ResourceVersion = ""
		// 	for {
		// 		_, err = clientset.BatchV1().Jobs(namespace).Get(w.Name, v1.GetOptions{})
		// 		if err != nil {
		// 			break
		// 		}
		// 		time.Sleep(time.Second * 1)
		// 	}
		// 	w, err = clientset.BatchV1().Jobs(namespace).Create(w)
		// }

	case "Pod":
		w := workload.(*corev1.Pod)
		injectPod(&w.ObjectMeta, &w.Spec, command, wlid)
		err = k8sworkloads.KubernetesClient.CoreV1().Pods(namespace).Delete(w.Name, &v1.DeleteOptions{})
		if err == nil {
			w.Status = corev1.PodStatus{}
			w.ObjectMeta.ResourceVersion = ""
			for {
				_, err = k8sworkloads.KubernetesClient.CoreV1().Pods(namespace).Get(w.Name, v1.GetOptions{})
				if err != nil {
					break
				}
				time.Sleep(time.Second * 1)
			}
			_, err = k8sworkloads.KubernetesClient.CoreV1().Pods(namespace).Create(w)
		}
	default:
		err = fmt.Errorf("command %s not supported with kind: %s", command, cautils.GetKindFromWlid(wlid))
	}
	return err

}

func inject(objectMeta *v1.ObjectMeta, template *corev1.PodTemplateSpec, command, wlid string, cmd *cautils.Command) {
	jobsAnnot := reporterlib.JobsAnnotations{}
	var annot []byte
	if jobid, hasJobID := cmd.Args["jobID"]; hasJobID {
		jobsAnnot.CurrJobID = fmt.Sprintf("%v", jobid)
		jobsAnnot.LastActionID = "3"

		annot, _ = json.Marshal(jobsAnnot)

	}
	switch command {
	case UPDATE:
		injectWlid(&template.ObjectMeta.Annotations, wlid)
		injectTime(&template.ObjectMeta.Annotations)
		injectLabel(&template.ObjectMeta.Labels)
		if len(jobsAnnot.CurrJobID) > 0 {
			template.ObjectMeta.Annotations[reporterlib.CAJobs] = string(annot)
		}
		removeAnnotation(&template.ObjectMeta, CAIgnoe)
		removeAnnotation(objectMeta, CAIgnoe)

	case RESTART:
		injectTime(&template.ObjectMeta.Annotations)
	case SIGN:
		updateLabel(&template.ObjectMeta.Labels)
		injectTime(&template.ObjectMeta.Annotations)
		if len(jobsAnnot.CurrJobID) > 0 {
			template.ObjectMeta.Annotations[reporterlib.CAJobs] = string(annot)
		}
	case REMOVE:
		restoreConatinerCommand(&template.Spec)
		removeCASpec(&template.Spec)
		removeCAMetadata(&template.ObjectMeta)
		injectAnnotation(&template.ObjectMeta.Annotations, CAIgnoe, "true")
		injectAnnotation(&objectMeta.Annotations, CAIgnoe, "true")
	}
	removeIDLabels(template.ObjectMeta.Labels)
}

func workloadUpdate(objectMeta *v1.ObjectMeta, command, wlid string) {
	switch command {
	case REMOVE:
		removeCAMetadata(objectMeta)
	}
}

func injectPod(metadata *v1.ObjectMeta, spec *corev1.PodSpec, command, wlid string) {
	switch command {
	case UPDATE:
		injectWlid(&metadata.Annotations, wlid)
		injectTime(&metadata.Annotations)
		injectAnnotation(&(metadata.Annotations), reporterlib.CAJobs, wlid)
		injectLabel(&metadata.Labels)
		removeAnnotation(metadata, CAIgnoe)
	case SIGN:
		updateLabel(&metadata.Labels)
		injectTime(&metadata.Annotations)
	case RESTART:
		injectTime(&metadata.Annotations)
	case REMOVE:
		restoreConatinerCommand(spec)
		removeCASpec(spec)
		removeCAMetadata(metadata)
		injectAnnotation(&metadata.Annotations, CAIgnoe, "true")

	}
	removeIDLabels(metadata.Labels)
}

func injectNS(metadata *v1.ObjectMeta, command string) {
	switch command {
	case INJECT:
		injectTime(&metadata.Annotations)
		injectLabel(&metadata.Labels)

	case REMOVE:
		removeCAMetadata(metadata)
	}
	removeIDLabels(metadata.Labels)
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

func removeAnnotation(meatdata *v1.ObjectMeta, key string) {
	if meatdata.Annotations != nil {
		delete(meatdata.Annotations, key)
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

func removeCAMetadata(meatdata *v1.ObjectMeta) {
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
	}
}

func cleanSelector(selector *v1.LabelSelector) {
	delete(selector.MatchLabels, controllerLable)
	if len(selector.MatchLabels) == 0 && len(selector.MatchLabels) == 0 {
		selector = &v1.LabelSelector{}
	}
}

func removeIDLabels(labels map[string]string) {
	delete(labels, controllerLable)
}

// excludeWlid - add a wlid to the ignore list
func excludeWlid(nsWlid, workloadWlid string) error {
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
	_, err = k8sworkloads.KubernetesClient.CoreV1().Namespaces().Update(w)
	return err
}

// excludeWlid - remove a wlid from the ignore list
func includeWlid(nsWlid, workloadWlid string) error {
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
	_, err = k8sworkloads.KubernetesClient.CoreV1().Namespaces().Update(w)
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
