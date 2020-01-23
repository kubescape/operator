package websocket

import (
	"fmt"
	"k8s-ca-websocket/k8sworkloads"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func getWorkload(wlid string) (interface{}, error) {
	microservice, err := RestoreMicroserviceIDsFromSpiffe(wlid)
	if err != nil {
		return nil, err
	}
	return getWorkloadFromK8S(microservice[1], microservice[2], microservice[3])
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
		return nil, fmt.Errorf("workload not found")

	case "ReplicaSet":
		w, _ := clientset.AppsV1().(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.AppsV1().Deployments(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("workload not found")
	case "DaemonSet":
		w, _ := clientset.AppsV1().DaemonSets(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.AppsV1().DaemonSets(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("workload not found")
	case "StatefulSet":
		w, _ := clientset.AppsV1().StatefulSets(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.AppsV1().StatefulSets(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("workload not found")
	case "PodTemplate":
		w, _ := clientset.CoreV1().PodTemplates(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.CoreV1().PodTemplates(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("workload not found")
	case "Pod":
		w, _ := clientset.CoreV1().Pods(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return clientset.CoreV1().Pods(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
	}
	return nil, fmt.Errorf("workload not found")

}
