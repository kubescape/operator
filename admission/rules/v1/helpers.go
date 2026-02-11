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

// GetControllerDetails returns the pod and controller details (pod, kind, name, namespace, and node name).
func GetControllerDetails(event admission.Attributes, clientset kubernetes.Interface) (*corev1.Pod, string, string, string, string, error) {
	podName, namespace := event.GetName(), event.GetNamespace()

	if podName == "" || namespace == "" {
		return nil, "", "", "", "", fmt.Errorf("invalid pod details from admission event")
	}

	pod, err := GetPodDetails(clientset, podName, namespace)
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("failed to get pod details: %w", err)
	}

	workloadKind, workloadName, workloadNamespace := ExtractPodOwner(pod, clientset)
	nodeName := pod.Spec.NodeName

	return pod, workloadKind, workloadName, workloadNamespace, nodeName, nil
}

// GetPodDetails returns the pod details from the Kubernetes API server.
func GetPodDetails(clientset kubernetes.Interface, podName, namespace string) (*corev1.Pod, error) {
	pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}
	return pod, nil
}

// ExtractPodOwner returns the kind, name, and namespace of the controller that owns the pod.
func ExtractPodOwner(pod *corev1.Pod, clientset kubernetes.Interface) (string, string, string) {
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

// GetWorkloadUID returns the UID of the workload (Deployment, StatefulSet, DaemonSet, CronJob, Job, or ReplicaSet).
// Returns an empty string if the workload cannot be found or if workloadKind/workloadName is empty.
func GetWorkloadUID(clientset kubernetes.Interface, workloadKind, workloadName, workloadNamespace string) string {
	if workloadKind == "" || workloadName == "" || workloadNamespace == "" {
		return ""
	}

	switch workloadKind {
	case "Deployment":
		deployment, err := clientset.AppsV1().Deployments(workloadNamespace).Get(context.TODO(), workloadName, metav1.GetOptions{})
		if err == nil {
			return string(deployment.UID)
		}
	case "StatefulSet":
		statefulSet, err := clientset.AppsV1().StatefulSets(workloadNamespace).Get(context.TODO(), workloadName, metav1.GetOptions{})
		if err == nil {
			return string(statefulSet.UID)
		}
	case "DaemonSet":
		daemonSet, err := clientset.AppsV1().DaemonSets(workloadNamespace).Get(context.TODO(), workloadName, metav1.GetOptions{})
		if err == nil {
			return string(daemonSet.UID)
		}
	case "CronJob":
		cronJob, err := clientset.BatchV1().CronJobs(workloadNamespace).Get(context.TODO(), workloadName, metav1.GetOptions{})
		if err == nil {
			return string(cronJob.UID)
		}
	case "Job":
		job, err := clientset.BatchV1().Jobs(workloadNamespace).Get(context.TODO(), workloadName, metav1.GetOptions{})
		if err == nil {
			return string(job.UID)
		}
	case "ReplicaSet":
		replicaSet, err := clientset.AppsV1().ReplicaSets(workloadNamespace).Get(context.TODO(), workloadName, metav1.GetOptions{})
		if err == nil {
			return string(replicaSet.UID)
		}
	}

	return ""
}
