package rules

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/kubernetes"
)

// GetControllerDetails returns the kind, name, namespace, and node name of the controller that owns the pod.
func GetControllerDetails(event admission.Attributes, clientset kubernetes.Interface) (string, string, string, string, error) {
	podName, namespace := event.GetName(), event.GetNamespace()

	if podName == "" || namespace == "" {
		return "", "", "", "", fmt.Errorf("invalid pod details from admission event")
	}

	pod, err := GetPodDetails(clientset, podName, namespace)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to get pod details: %v", err)
	}

	workloadKind, workloadName, workloadNamespace := ExtractPodOwner(pod, clientset)
	nodeName := pod.Spec.NodeName

	return workloadKind, workloadName, workloadNamespace, nodeName, nil
}

// GetPodDetails returns the pod details from the Kubernetes API server.
func GetPodDetails(clientset kubernetes.Interface, podName, namespace string) (*v1.Pod, error) {
	pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %v", err)
	}
	return pod, nil
}

// ExtractPodOwner returns the kind, name, and namespace of the controller that owns the pod.
func ExtractPodOwner(pod *v1.Pod, clientset kubernetes.Interface) (string, string, string) {
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

// resolveReplicaSet returns the kind, name, and namespace of the controller that owns the replica set.
func resolveReplicaSet(ownerRef metav1.OwnerReference, namespace string, clientset kubernetes.Interface) (string, string, string) {
	rs, err := clientset.AppsV1().ReplicaSets(namespace).Get(context.TODO(), ownerRef.Name, metav1.GetOptions{})
	if err == nil && len(rs.OwnerReferences) > 0 && rs.OwnerReferences[0].Kind == "Deployment" {
		return "Deployment", rs.OwnerReferences[0].Name, namespace
	}
	return "ReplicaSet", ownerRef.Name, namespace
}

// resolveJob resolves the owner of a Kubernetes Job resource.
// It checks if the given Job is owned by a CronJob, and if so, it returns the CronJob's details.
// Otherwise, it returns the Job's details.
func resolveJob(ownerRef metav1.OwnerReference, namespace string, clientset kubernetes.Interface) (string, string, string) {
	job, err := clientset.BatchV1().Jobs(namespace).Get(context.TODO(), ownerRef.Name, metav1.GetOptions{})
	if err == nil && len(job.OwnerReferences) > 0 && job.OwnerReferences[0].Kind == "CronJob" {
		return "CronJob", job.OwnerReferences[0].Name, namespace
	}
	return "Job", ownerRef.Name, namespace
}

// GetContainerNameFromExecToPodEvent returns the container name from the admission event for exec operations.
func GetContainerNameFromExecToPodEvent(event admission.Attributes) (string, error) {
	if event.GetSubresource() != "exec" {
		return "", fmt.Errorf("not an exec subresource")
	}

	obj := event.GetObject()
	if obj == nil {
		return "", fmt.Errorf("event object is nil")
	}

	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return "", fmt.Errorf("object is not of type *unstructured.Unstructured")
	}

	podExecOptions := &v1.PodExecOptions{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, podExecOptions); err != nil {
		return "", fmt.Errorf("failed to decode PodExecOptions: %v", err)
	}

	return podExecOptions.Container, nil
}
