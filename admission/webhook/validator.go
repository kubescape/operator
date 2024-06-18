package webhook

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	exporters "github.com/kubescape/operator/admission/exporter"
	v1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
)

// TODO: Implement the validations in a separate package.

type AdmissionValidator struct {
	kubernetesClient *k8sinterface.KubernetesApi
	exporter         *exporters.HTTPExporter
}

func NewAdmissionValidator(kubernetesClient *k8sinterface.KubernetesApi, exporter *exporters.HTTPExporter) *AdmissionValidator {
	return &AdmissionValidator{
		kubernetesClient: kubernetesClient,
		exporter:         exporter,
	}
}

// We are implementing the Validate method from the ValidationInterface interface.
func (av *AdmissionValidator) Validate(ctx context.Context, attrs admission.Attributes, o admission.ObjectInterfaces) (err error) {
	kind := attrs.GetKind().GroupKind().Kind
	resource := attrs.GetResource().Resource

	switch {
	case kind == "Pod" || resource == "pods":
		// If the request is for a pod, we call the validatePods function to validate the request.
		return av.validatePods(attrs)
	case kind == "ClusterRoleBinding" || resource == "clusterrolebindings":
		// If the request is for a clusterRoleBinding, we call the validateClusterRoleBinding function to validate the request.
		return av.validateAdminClusterRoleBinding(attrs)
	case kind == "RoleBinding" || resource == "rolebindings":
		// If the request is for a roleBinding, we call the validateRoleBinding function to validate the request.
		return av.validateAdminRoleBinding(attrs)
	default:
		return nil
	}
}

// We are implementing the Handles method from the ValidationInterface interface.
// This method returns true if this admission controller can handle the given operation, we accept all operations.
func (av *AdmissionValidator) Handles(operation admission.Operation) bool {
	return true
}

func (av *AdmissionValidator) validateAdminRoleBinding(attrs admission.Attributes) error {
	// Check if the request is for roleBinding creation.
	if attrs.GetOperation() == admission.Create {
		var roleBinding *rbac.RoleBinding
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(attrs.GetObject().(*unstructured.Unstructured).Object, &roleBinding)
		if err != nil {
			return nil
		}

		// Fetch the role from the k8s API.
		role, err := av.kubernetesClient.KubernetesClient.RbacV1().Roles(roleBinding.GetNamespace()).Get(context.Background(), roleBinding.RoleRef.Name, metav1.GetOptions{})
		if err != nil {
			logger.L().Debug("Error fetching role", helpers.Error(err))
			return nil
		}

		// If the role has * in the verbs, resources or apiGroups, return an error.
		for _, rule := range role.Rules {
			if slices.Contains(rule.Verbs, "*") && slices.Contains(rule.Resources, "*") && (slices.Contains(rule.APIGroups, "*") || slices.Contains(rule.APIGroups, "")) {
				av.exporter.SendAdmissionAlert(&attrs, "R2006", fmt.Sprintf("roleBinding with wildcard role %s", attrs.GetName()))
				return admission.NewForbidden(attrs, fmt.Errorf("roleBinding with wildcard role is audited"))
			}
		}
	}

	return nil
}

func (av *AdmissionValidator) validateAdminClusterRoleBinding(attrs admission.Attributes) error {
	// Check if the request is for clusterRoleBinding creation.
	if attrs.GetOperation() == admission.Create {
		var clusterRoleBinding *rbac.ClusterRoleBinding
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(attrs.GetObject().(*unstructured.Unstructured).Object, &clusterRoleBinding)
		if err != nil {
			return nil
		}

		// Fetch the role from the k8s API.
		role, err := av.kubernetesClient.KubernetesClient.RbacV1().ClusterRoles().Get(context.Background(), clusterRoleBinding.RoleRef.Name, metav1.GetOptions{})
		if err != nil {
			logger.L().Debug("Error fetching role", helpers.Error(err))
			return nil
		}

		// If the role has * in the verbs, resources or apiGroups, return an error.
		for _, rule := range role.Rules {
			if slices.Contains(rule.Verbs, "*") && slices.Contains(rule.Resources, "*") && (slices.Contains(rule.APIGroups, "*") || slices.Contains(rule.APIGroups, "")) {
				av.exporter.SendAdmissionAlert(&attrs, "R2005", fmt.Sprintf("clusterRoleBinding with wildcard role %s", attrs.GetName()))
				return admission.NewForbidden(attrs, fmt.Errorf("clusterRoleBinding with wildcard role is audited"))
			}
		}
	}

	return nil
}

func (av *AdmissionValidator) validatePods(attrs admission.Attributes) error {
	var errs error

	// Check if the request is for pod exec or attach.
	if attrs.GetSubresource() == "exec" {
		av.exporter.SendAdmissionAlert(&attrs, "R2000", fmt.Sprintf("exec to pod %s", attrs.GetName()))
		errs = errors.Join(errs, admission.NewForbidden(attrs, fmt.Errorf("exec to pod is audited")))
	}

	if attrs.GetSubresource() == "attach" {
		av.exporter.SendAdmissionAlert(&attrs, "R2001", fmt.Sprintf("attach to pod %s", attrs.GetName()))
		errs = errors.Join(errs, admission.NewForbidden(attrs, fmt.Errorf("attach to pod is audited")))
	}

	// Check if the request is for privileged container creation.
	if attrs.GetOperation() == admission.Create {
		pod, ok := attrs.GetObject().(*v1.Pod)
		if !ok {
			return nil
		}

		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				av.exporter.SendAdmissionAlert(&attrs, "R2002", fmt.Sprintf("privileged container in pod %s", attrs.GetName()))
				errs = errors.Join(errs, admission.NewForbidden(attrs, fmt.Errorf("privileged container creation is audited")))
			}
		}
	}

	// Check if the request is for pod with insecure capabilities (SYS_ADMIN, SYS_MODULE, NET_ADMIN, NET_RAW, SYS_PTRACE, SYS_BOOT, SYS_RAWIO, BPF).
	if attrs.GetOperation() == admission.Create {
		pod, ok := attrs.GetObject().(*v1.Pod)
		if !ok {
			return nil
		}

		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
				for _, capability := range container.SecurityContext.Capabilities.Add {
					if capability == "SYS_ADMIN" || capability == "SYS_MODULE" || capability == "NET_ADMIN" || capability == "NET_RAW" || capability == "SYS_PTRACE" || capability == "SYS_BOOT" || capability == "SYS_RAWIO" || capability == "BPF" {
						av.exporter.SendAdmissionAlert(&attrs, "R2003", fmt.Sprintf("insecure capability in pod %s", attrs.GetName()))
						errs = errors.Join(errs, admission.NewForbidden(attrs, fmt.Errorf("insecure capability is audited")))
					}
				}
			}
		}
	}

	// Check if the request is for pod with hostMounts.
	if attrs.GetOperation() == admission.Create {
		pod, ok := attrs.GetObject().(*v1.Pod)
		if !ok {
			return nil
		}

		for _, volume := range pod.Spec.Volumes {
			// If a volume is a hostPath, return an error.
			if volume.HostPath != nil {
				av.exporter.SendAdmissionAlert(&attrs, "R2004", fmt.Sprintf("hostPath volume in pod %s", attrs.GetName()))
				errs = errors.Join(errs, admission.NewForbidden(attrs, fmt.Errorf("hostPath volume is audited")))
			}
		}
	}

	// Check if the request is for port-forwarding.
	if attrs.GetSubresource() == "portforward" {
		errs = errors.Join(errs, admission.NewForbidden(attrs, fmt.Errorf("port-forwarding is audited")))
	}

	return errs
}
