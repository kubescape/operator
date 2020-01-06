package websocket

import (
	"k8s-ca-websocket/k8sworkloads"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

func updateWorkload(workload interface{}, wlid string) error {
	microservice, _ := RestoreMicroserviceIDsFromSpiffe(wlid)
	namespace, kind := microservice[1], microservice[2]
	clientset, err := kubernetes.NewForConfig(k8sworkloads.GetK8sConfig())
	if err != nil {
		return err
	}
	switch kind {
	case "Deployment":
		w := workload.(*appsv1.Deployment)
		injectWlid(w.Spec.Template.ObjectMeta.Annotations, wlid)
		go clientset.AppsV1().Deployments(namespace).Update(w)

	case "ReplicaSet":
		w := workload.(*appsv1.ReplicaSet)
		injectWlid(w.Spec.Template.ObjectMeta.Annotations, wlid)
		go clientset.AppsV1().ReplicaSets(namespace).Update(w)

	case "DaemonSet":
		w := workload.(*appsv1.DaemonSet)
		injectWlid(w.Spec.Template.ObjectMeta.Annotations, wlid)
		go clientset.AppsV1().DaemonSets(namespace).Update(w)

	case "StatefulSet":
		w := workload.(*appsv1.StatefulSet)
		injectWlid(w.Spec.Template.ObjectMeta.Annotations, wlid)
		go clientset.AppsV1().StatefulSets(namespace).Update(w)

	case "PodTemplate":
		w := workload.(*corev1.PodTemplate)
		injectWlid(w.ObjectMeta.Annotations, wlid)
		go clientset.CoreV1().PodTemplates(namespace).Update(w)

	case "Pod":
		w := workload.(*corev1.Pod)
		injectWlid(w.ObjectMeta.Annotations, wlid)
		go clientset.CoreV1().Pods(namespace).Update(w)
	}
	return nil

}

func injectWlid(annotations map[string]string, wlid string) {
	if annotations == nil {
		annotations = make(map[string]string)

	}
	annotations["wlid"] = wlid
	annotations["latets-catriger-update"] = string(time.Now().UTC().Format("02-01-2006 15:04:05"))
}
