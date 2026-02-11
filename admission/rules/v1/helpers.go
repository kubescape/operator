package rules

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/kubernetes"
)

// GetControllerDetails returns the pod and controller details (pod, kind, name, namespace, uid, and node name).
// The workload UID is captured during owner resolution to avoid duplicate API calls.
func GetControllerDetails(event admission.Attributes, clientset kubernetes.Interface) (*corev1.Pod, string, string, string, string, string, error) {
	podName, namespace := event.GetName(), event.GetNamespace()

	if podName == "" || namespace == "" {
		return nil, "", "", "", "", "", fmt.Errorf("invalid pod details from admission event")
	}

	pod, err := GetPodDetails(clientset, podName, namespace)
	if err != nil {
		return nil, "", "", "", "", "", fmt.Errorf("failed to get pod details: %w", err)
	}

	workloadKind, workloadName, workloadNamespace, workloadUID := ExtractPodOwner(pod, clientset)
	nodeName := pod.Spec.NodeName

	return pod, workloadKind, workloadName, workloadNamespace, workloadUID, nodeName, nil
}

// GetPodDetails returns the pod details from the Kubernetes API server.
func GetPodDetails(clientset kubernetes.Interface, podName, namespace string) (*corev1.Pod, error) {
	pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}
	return pod, nil
}

// ExtractPodOwner returns the kind, name, namespace, and UID of the controller that owns the pod.
// The UID is captured from OwnerReferences or during resolution to avoid duplicate API calls.
func ExtractPodOwner(pod *corev1.Pod, clientset kubernetes.Interface) (string, string, string, string) {
	for _, ownerRef := range pod.OwnerReferences {
		switch ownerRef.Kind {
		case "ReplicaSet":
			return resolveReplicaSet(ownerRef, pod.Namespace, clientset)
		case "Job":
			return resolveJob(ownerRef, pod.Namespace, clientset)
		case "StatefulSet", "DaemonSet":
			return ownerRef.Kind, ownerRef.Name, pod.Namespace, string(ownerRef.UID)
		}
	}
	return "", "", "", ""
}

// resolveReplicaSet returns the kind, name, namespace, and UID of the controller that owns the replica set.
// If the ReplicaSet is owned by a Deployment, returns the Deployment's details; otherwise returns the ReplicaSet's details.
func resolveReplicaSet(ownerRef metav1.OwnerReference, namespace string, clientset kubernetes.Interface) (string, string, string, string) {
	rs, err := clientset.AppsV1().ReplicaSets(namespace).Get(context.TODO(), ownerRef.Name, metav1.GetOptions{})
	if err == nil && len(rs.OwnerReferences) > 0 && rs.OwnerReferences[0].Kind == "Deployment" {
		return "Deployment", rs.OwnerReferences[0].Name, namespace, string(rs.OwnerReferences[0].UID)
	}
	// If no Deployment parent or GET failed, use ReplicaSet's UID from the original ownerRef
	return "ReplicaSet", ownerRef.Name, namespace, string(ownerRef.UID)
}

// resolveJob resolves the owner of a Kubernetes Job resource.
// It checks if the given Job is owned by a CronJob, and if so, it returns the CronJob's details including UID.
// Otherwise, it returns the Job's details.
func resolveJob(ownerRef metav1.OwnerReference, namespace string, clientset kubernetes.Interface) (string, string, string, string) {
	job, err := clientset.BatchV1().Jobs(namespace).Get(context.TODO(), ownerRef.Name, metav1.GetOptions{})
	if err == nil && len(job.OwnerReferences) > 0 && job.OwnerReferences[0].Kind == "CronJob" {
		return "CronJob", job.OwnerReferences[0].Name, namespace, string(job.OwnerReferences[0].UID)
	}
	// If no CronJob parent or GET failed, use Job's UID from the original ownerRef
	return "Job", ownerRef.Name, namespace, string(ownerRef.UID)
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

	podExecOptions := &corev1.PodExecOptions{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, podExecOptions); err != nil {
		return "", fmt.Errorf("failed to decode PodExecOptions: %w", err)
	}

	return podExecOptions.Container, nil
}

// GetContainerID returns the container ID for the given container name from the pod status.
// It checks regular containers, init containers, and ephemeral containers.
// When containerName is empty, falls back to the first container (matching Kubernetes default behavior).
// Returns an empty string if the container is not found or pod is nil.
func GetContainerID(pod *corev1.Pod, containerName string) string {
	if pod == nil {
		return ""
	}

	// If containerName is empty, Kubernetes defaults to the first container
	if containerName == "" {
		if len(pod.Status.ContainerStatuses) > 0 {
			return pod.Status.ContainerStatuses[0].ContainerID
		}
		return ""
	}

	// Check regular containers
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == containerName {
			return cs.ContainerID
		}
	}

	// Check init containers
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.Name == containerName {
			return cs.ContainerID
		}
	}

	// Check ephemeral containers (debug containers)
	for _, cs := range pod.Status.EphemeralContainerStatuses {
		if cs.Name == containerName {
			return cs.ContainerID
		}
	}

	return ""
}
