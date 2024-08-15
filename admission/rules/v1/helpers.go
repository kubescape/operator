package rules

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/kubernetes"
)

func GetParentWorkloadDetails(event admission.Attributes, clientset kubernetes.Interface) (string, string, string, string, error) {
	podName, namespace := event.GetName(), event.GetNamespace()

	if podName == "" || namespace == "" {
		return "", "", "", "", fmt.Errorf("invalid pod details from admission event")
	}

	pod, err := GetPodDetails(clientset, podName, namespace)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to get pod details: %v", err)
	}

	workloadKind, workloadName, workloadNamespace := ExtractPodInformation(pod, clientset)
	nodeName := pod.Spec.NodeName

	return workloadKind, workloadName, workloadNamespace, nodeName, nil
}

func GetPodDetails(clientset kubernetes.Interface, podName, namespace string) (*v1.Pod, error) {
	pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %v", err)
	}
	return pod, nil
}

func ExtractPodInformation(pod *v1.Pod, clientset kubernetes.Interface) (string, string, string) {
	for _, ownerRef := range pod.OwnerReferences {
		switch ownerRef.Kind {
		case "ReplicaSet":
			return resolveReplicaSet(ownerRef, pod.Namespace, clientset)
		case "Job":
			return resolveJob(ownerRef, pod.Namespace, clientset)
		case "StatefulSet", "DaemonSet":
			return ownerRef.Kind, ownerRef.Name, pod.Namespace
		}
	}
	return "", "", ""
}

func resolveReplicaSet(ownerRef metav1.OwnerReference, namespace string, clientset kubernetes.Interface) (string, string, string) {
	rs, err := clientset.AppsV1().ReplicaSets(namespace).Get(context.TODO(), ownerRef.Name, metav1.GetOptions{})
	if err == nil && len(rs.OwnerReferences) > 0 && rs.OwnerReferences[0].Kind == "Deployment" {
		return "Deployment", rs.OwnerReferences[0].Name, namespace
	}
	return "ReplicaSet", ownerRef.Name, namespace
}

func resolveJob(ownerRef metav1.OwnerReference, namespace string, clientset kubernetes.Interface) (string, string, string) {
	job, err := clientset.BatchV1().Jobs(namespace).Get(context.TODO(), ownerRef.Name, metav1.GetOptions{})
	if err == nil && len(job.OwnerReferences) > 0 && job.OwnerReferences[0].Kind == "CronJob" {
		return "CronJob", job.OwnerReferences[0].Name, namespace
	}
	return "Job", ownerRef.Name, namespace
}