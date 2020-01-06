package websocket

import (
	"k8s-ca-websocket/k8sworkloads"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func removeWorkload(workload interface{}, wlid string) error {
	microservice, _ := RestoreMicroserviceIDsFromSpiffe(wlid)
	namespace, kind := microservice[1], microservice[2]
	clientset, err := kubernetes.NewForConfig(k8sworkloads.GetK8sConfig())
	if err != nil {
		return err
	}
	switch kind {
	case "deployment":
		w := workload.(appsv1.Deployment)
		removeCA(&w.ObjectMeta)
		removeCA(&w.Spec.Template.ObjectMeta)
		go clientset.AppsV1().Deployments(namespace).Update(&w)

	case "replicaSet":
		w := workload.(appsv1.ReplicaSet)
		removeCA(&w.ObjectMeta)
		removeCA(&w.Spec.Template.ObjectMeta)
		go clientset.AppsV1().ReplicaSets(namespace).Update(&w)

	case "daemonSet":
		w := workload.(appsv1.DaemonSet)
		removeCA(&w.ObjectMeta)
		removeCA(&w.Spec.Template.ObjectMeta)
		go clientset.AppsV1().DaemonSets(namespace).Update(&w)

	case "statefulSet":
		w := workload.(appsv1.StatefulSet)
		removeCA(&w.ObjectMeta)
		removeCA(&w.Spec.Template.ObjectMeta)
		go clientset.AppsV1().StatefulSets(namespace).Update(&w)

	case "podTemplate":
		w := workload.(corev1.PodTemplate)
		removeCA(&w.ObjectMeta)
		go clientset.CoreV1().PodTemplates(namespace).Update(&w)

	case "pod":
		w := workload.(corev1.Pod)
		removeCA(&w.ObjectMeta)
		go clientset.CoreV1().Pods(namespace).Update(&w)
	}
	return nil

}

func removeCA(meatdata *v1.ObjectMeta) {
	delete(meatdata.Labels, CAInject)
	delete(meatdata.Labels, CALabel)
	delete(meatdata.Annotations, "wlid")
	delete(meatdata.Annotations, "caGUIDs")
}
