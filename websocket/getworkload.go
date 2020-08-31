package websocket

import (
	"fmt"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/k8sworkloads"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func getWorkload(wlid string) (interface{}, error) {
	microservice, err := cautils.RestoreMicroserviceIDsFromSpiffe(wlid)
	if err != nil {
		return nil, err
	}
	return getWorkloadFromK8S(microservice[1], cautils.GetKindFromWlid(wlid), microservice[3])
}

func getWorkloadFromK8S(namespace, kind, name string) (interface{}, error) {

	clientset, err := kubernetes.NewForConfig(k8sworkloads.GetK8sConfig())
	if err != nil {
		return nil, err
	}
	switch kind {
	case "Deployment":
		w, _ := clientset.AppsV1().Deployments(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.AppsV1().Deployments(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("Deployment '%s' not found in namespace: %s", name, namespace)

	case "ReplicaSet":
		w, _ := clientset.AppsV1().ReplicaSets(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.AppsV1().ReplicaSets(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("ReplicaSet '%s' not found in namespace: %s", name, namespace)
	case "DaemonSet":
		w, _ := clientset.AppsV1().DaemonSets(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.AppsV1().DaemonSets(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("DaemonSet '%s' not found in namespace: %s", name, namespace)
	case "StatefulSet":
		w, _ := clientset.AppsV1().StatefulSets(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.AppsV1().StatefulSets(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("StatefulSet '%s' not found in namespace: %s", name, namespace)
	case "Job":
		w, _ := clientset.BatchV1().Jobs(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.BatchV1().Jobs(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("Job '%s' not found in namespace: %s", name, namespace)
	case "PodTemplate":
		w, _ := clientset.CoreV1().PodTemplates(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.CoreV1().PodTemplates(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("PodTemplate '%s' not found in namespace: %s", name, namespace)
	case "Pod":
		w, _ := clientset.CoreV1().Pods(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.CoreV1().Pods(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("Pod '%s' not found in namespace: %s", name, namespace)
	case "Namespace":
		w, _ := clientset.CoreV1().Namespaces().List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.CoreV1().Namespaces().Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("Namespace '%s' not found", namespace)
	}
	return nil, fmt.Errorf("kind: %s unknown", kind)

}
