package websocket

import (
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/k8sworkloads"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	// corev1beta1 "k8s.io/api/core/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func updateWorkload(wlid string, command string) error {
	var err error
	namespace := cautils.GetNamespaceFromWlid(wlid)
	kind := cautils.GetKindFromWlid(wlid)
	clientset, e := kubernetes.NewForConfig(k8sworkloads.GetK8sConfig())
	if e != nil {
		return e
	}
	workload, err := getWorkload(wlid)
	if err != nil {
		return err
	}

	switch kind {
	case "Namespace":
		w := workload.(*corev1.Namespace)
		injectNS(&w.ObjectMeta, command)
		_, err = clientset.CoreV1().Namespaces().Update(w)

	case "Deployment":
		w := workload.(*appsv1.Deployment)
		inject(&w.Spec.Template, command, wlid)
		_, err = clientset.AppsV1().Deployments(namespace).Update(w)

	case "ReplicaSet":
		w := workload.(*appsv1.ReplicaSet)
		inject(&w.Spec.Template, command, wlid)
		_, err = clientset.AppsV1().ReplicaSets(namespace).Update(w)

	case "DaemonSet":
		w := workload.(*appsv1.DaemonSet)
		inject(&w.Spec.Template, command, wlid)
		_, err = clientset.AppsV1().DaemonSets(namespace).Update(w)

	case "StatefulSet":
		w := workload.(*appsv1.StatefulSet)
		inject(&w.Spec.Template, command, wlid)
		// glog.Infof("updating %s: %v", kind, w)
		w, err = clientset.AppsV1().StatefulSets(namespace).Update(w)
		// glog.Infof("after updating %s: %v", kind, w)

	case "PodTemplate":
		w := workload.(*corev1.PodTemplate)
		inject(&w.Template, command, wlid)
		_, err = clientset.CoreV1().PodTemplates(namespace).Update(w)

	case "Job":
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
		err = clientset.CoreV1().Pods(namespace).Delete(w.Name, &v1.DeleteOptions{})
		if err == nil {
			w.Status = corev1.PodStatus{}
			w.ObjectMeta.ResourceVersion = ""
			for {
				_, err = clientset.CoreV1().Pods(namespace).Get(w.Name, v1.GetOptions{})
				if err != nil {
					break
				}
				time.Sleep(time.Second * 1)
			}
			_, err = clientset.CoreV1().Pods(namespace).Create(w)
		}
	}
	return err

}

func inject(template *corev1.PodTemplateSpec, command, wlid string) {
	switch command {
	case UPDATE:
		injectWlid(&template.ObjectMeta.Annotations, wlid)
		injectTime(&template.ObjectMeta.Annotations)
		injectLabel(&template.ObjectMeta.Labels)

	case SIGN:
		updateLabel(&template.ObjectMeta.Labels)
		injectTime(&template.ObjectMeta.Annotations)
	case REMOVE:
		removeCASpec(&template.Spec)
		removeCAMetadata(&template.ObjectMeta)
	}
	removeIDLabels(template.ObjectMeta.Labels)
}

func injectPod(metadata *v1.ObjectMeta, spec *corev1.PodSpec, command, wlid string) {
	switch command {
	case UPDATE:
		injectWlid(&metadata.Annotations, wlid)
		injectTime(&metadata.Annotations)
		injectLabel(&metadata.Labels)

	case SIGN:
		updateLabel(&metadata.Labels)
		injectTime(&metadata.Annotations)
	case REMOVE:
		removeCASpec(spec)
		removeCAMetadata(metadata)
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

	// remove LD_PRELOAD environment
	for i := range spec.Containers {
		removeEnvironmentVariable(spec.Containers[i].Env, "LD_PRELOAD")
	}
}

func removeEnvironmentVariable(envs []corev1.EnvVar, env string) {
	nOfEnvs := len(envs)
	for i := 0; i < nOfEnvs; i++ {
		if envs[i].Name == env {
			if nOfEnvs < 2 { //i is the only element in the slice so we need to remove this entry from the map
				envs = []corev1.EnvVar{}
			} else if i == nOfEnvs-1 { // i is the last element in the slice so i+1 is out of range
				envs = envs[:i]
			} else {
				envs = append(envs[:i], envs[i+1:]...)
			}
			nOfEnvs--
			i--
		}
	}
}

func injectWlid(annotations *map[string]string, wlid string) {
	if *annotations == nil {
		(*annotations) = make(map[string]string)
	}
	(*annotations)["wlid"] = wlid
}

func injectTime(annotations *map[string]string) {
	if *annotations == nil {
		(*annotations) = make(map[string]string)
	}
	(*annotations)["latets-catriger-update"] = string(time.Now().UTC().Format("02-01-2006 15:04:05"))
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
}

func removeCAMetadata(meatdata *v1.ObjectMeta) {
	delete(meatdata.Labels, CAInject)
	delete(meatdata.Labels, CALabel)
	delete(meatdata.Annotations, "wlid")
	delete(meatdata.Annotations, CAStatus)
	delete(meatdata.Annotations, CASigned)
	delete(meatdata.Annotations, CAWlid)
	delete(meatdata.Annotations, CAAttached)
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
