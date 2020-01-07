package websocket

import (
	"k8s-ca-websocket/k8sworkloads"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func updateWorkload(workload interface{}, wlid string, command string) error {
	microservice, _ := RestoreMicroserviceIDsFromSpiffe(wlid)
	namespace, kind := microservice[1], microservice[2]
	clientset, err := kubernetes.NewForConfig(k8sworkloads.GetK8sConfig())
	if err != nil {
		return err
	}
	switch kind {
	case "Deployment":
		w := workload.(*appsv1.Deployment)
		inject(&w.Spec.Template.ObjectMeta, command, wlid)
		go clientset.AppsV1().Deployments(namespace).Update(w)

	case "ReplicaSet":
		w := workload.(*appsv1.ReplicaSet)
		inject(&w.Spec.Template.ObjectMeta, command, wlid)
		go clientset.AppsV1().ReplicaSets(namespace).Update(w)

	case "DaemonSet":
		w := workload.(*appsv1.DaemonSet)
		inject(&w.Spec.Template.ObjectMeta, command, wlid)
		go clientset.AppsV1().DaemonSets(namespace).Update(w)

	case "StatefulSet":
		w := workload.(*appsv1.StatefulSet)
		inject(&w.Spec.Template.ObjectMeta, command, wlid)
		go clientset.AppsV1().StatefulSets(namespace).Update(w)

	case "PodTemplate":
		w := workload.(*corev1.PodTemplate)
		inject(&w.ObjectMeta, command, wlid)
		go clientset.CoreV1().PodTemplates(namespace).Update(w)

	case "Pod":
		w := workload.(*corev1.Pod)
		inject(&w.ObjectMeta, command, wlid)
		go clientset.CoreV1().Pods(namespace).Update(w)
	}
	return nil

}

func inject(metadata *v1.ObjectMeta, command, wlid string) {
	switch command {
	case UPDATE:
		injectWlid(&metadata.Annotations, wlid)
		injectTime(&metadata.Annotations)

	case SIGN:
		updateLabel(&metadata.Labels)
		injectTime(&metadata.Annotations)

	case REMOVE:
		removeCAMetadata(metadata)
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

func removeCAMetadata(meatdata *v1.ObjectMeta) {
	delete(meatdata.Labels, CAInject)
	delete(meatdata.Labels, CALabel)
	delete(meatdata.Annotations, "wlid")
}
