package websocket

import (
	"fmt"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/k8sworkloads"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getWorkload(wlid string) (interface{}, error) {
	microservice, err := cautils.RestoreMicroserviceIDsFromSpiffe(wlid)
	if err != nil {
		return nil, err
	}
	return getWorkloadFromK8S(microservice[1], cautils.GetKindFromWlid(wlid), microservice[3])
}

func getWorkloadFromK8S(namespace, kind, name string) (interface{}, error) {

	switch kind {
	case "Deployment":
		w, _ := k8sworkloads.KubernetesClient.AppsV1().Deployments(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return k8sworkloads.KubernetesClient.AppsV1().Deployments(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("Deployment '%s' not found in namespace: %s", name, namespace)

	case "ReplicaSet":
		w, _ := k8sworkloads.KubernetesClient.AppsV1().ReplicaSets(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return k8sworkloads.KubernetesClient.AppsV1().ReplicaSets(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("ReplicaSet '%s' not found in namespace: %s", name, namespace)
	case "DaemonSet":
		w, _ := k8sworkloads.KubernetesClient.AppsV1().DaemonSets(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return k8sworkloads.KubernetesClient.AppsV1().DaemonSets(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("DaemonSet '%s' not found in namespace: %s", name, namespace)
	case "StatefulSet":
		w, _ := k8sworkloads.KubernetesClient.AppsV1().StatefulSets(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return k8sworkloads.KubernetesClient.AppsV1().StatefulSets(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("StatefulSet '%s' not found in namespace: %s", name, namespace)
	case "Job":
		w, _ := k8sworkloads.KubernetesClient.BatchV1().Jobs(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return k8sworkloads.KubernetesClient.BatchV1().Jobs(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("Job '%s' not found in namespace: %s", name, namespace)
	case "CronJob":
		w, _ := k8sworkloads.KubernetesClient.BatchV1beta1().CronJobs(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return k8sworkloads.KubernetesClient.BatchV1beta1().CronJobs(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("Job '%s' not found in namespace: %s", name, namespace)

	case "PodTemplate":
		w, _ := k8sworkloads.KubernetesClient.CoreV1().PodTemplates(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return k8sworkloads.KubernetesClient.CoreV1().PodTemplates(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("PodTemplate '%s' not found in namespace: %s", name, namespace)
	case "Pod":
		w, _ := k8sworkloads.KubernetesClient.CoreV1().Pods(namespace).List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return k8sworkloads.KubernetesClient.CoreV1().Pods(namespace).Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("Pod '%s' not found in namespace: %s", name, namespace)
	case "Namespace":
		w, _ := k8sworkloads.KubernetesClient.CoreV1().Namespaces().List(v1.ListOptions{})
		for _, i := range w.Items {
			if i.Name == name {
				return k8sworkloads.KubernetesClient.CoreV1().Namespaces().Get(i.Name, v1.GetOptions{})
			}
		}
		return nil, fmt.Errorf("Namespace '%s' not found", namespace)
	}
	return nil, fmt.Errorf("kind: %s unknown", kind)

}

func getWorkloadImages(wlid, command string) ([]string, error) {
	kind := cautils.GetKindFromWlid(wlid)

	images := make(map[string]bool)

	workload, err := getWorkload(wlid)
	if err != nil {
		return []string{}, err
	}

	switch kind {
	// case "Namespace":
	// 	w := workload.(*corev1.Namespace)
	// 	injectNS(&w.ObjectMeta, command)
	// 	_, err = k8sworkloads.KubernetesClient.CoreV1().Namespaces().Update(w)

	case "Deployment":
		w := workload.(*appsv1.Deployment)
		for i := range w.Spec.Template.Spec.Containers {
			images[w.Spec.Template.Spec.Containers[i].Image] = true
		}
	case "ReplicaSet":
		w := workload.(*appsv1.ReplicaSet)
		for i := range w.Spec.Template.Spec.Containers {
			images[w.Spec.Template.Spec.Containers[i].Image] = true
		}
	case "DaemonSet":
		w := workload.(*appsv1.DaemonSet)
		for i := range w.Spec.Template.Spec.Containers {
			images[w.Spec.Template.Spec.Containers[i].Image] = true
		}
	case "StatefulSet":
		w := workload.(*appsv1.StatefulSet)
		for i := range w.Spec.Template.Spec.Containers {
			images[w.Spec.Template.Spec.Containers[i].Image] = true
		}
	case "PodTemplate":
		w := workload.(*corev1.PodTemplate)
		for i := range w.Template.Spec.Containers {
			images[w.Template.Spec.Containers[i].Image] = true
		}
	case "CronJob":
		// w := workload.(*v1beta1.CronJob)
		// for i := range w.Spec.JobTemplate. {
		// 	images[w.Template.Spec.Containers[i]] = true
		// }
	case "Job":
		// w := workload.(*v1beta1.Job)
		// for i := range w. {
		// 	images[w.Template.Spec.Containers[i]] = true
		// }

	case "Pod":
		w := workload.(*corev1.Pod)
		for i := range w.Spec.Containers {
			images[w.Spec.Containers[i].Image] = true
		}
	default:
		err = fmt.Errorf("command %s not supported with kind: %s", command, cautils.GetKindFromWlid(wlid))
	}

	listImages := []string{}
	for i := range images {
		listImages = append(listImages, i)
	}
	return listImages, nil

}
