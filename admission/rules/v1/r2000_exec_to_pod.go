package rules

import (
	"fmt"

	"github.com/kubescape/operator/admission/rules"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	corev1 "k8s.io/api/core/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
)

const (
	R2000ID   = "R2000"
	R2000Name = "Exec to pod"
)

var R2000ExecToPodRuleDescriptor = RuleDescriptor{
	ID:          R2000ID,
	Name:        R2000Name,
	Description: "Detecting exec to pod",
	Tags:        []string{"exec"},
	Priority:    RulePriorityMed,
	RuleCreationFunc: func() rules.RuleEvaluator {
		return CreateRuleR2000ExecToPod()
	},
}

type R2000ExecToPod struct {
	BaseRule
}

func CreateRuleR2000ExecToPod() *R2000ExecToPod {
	return &R2000ExecToPod{}
}
func (rule *R2000ExecToPod) Name() string {
	return R2000Name
}

func (rule *R2000ExecToPod) ID() string {
	return R2000ID
}

func (rule *R2000ExecToPod) DeleteRule() {
}

func (rule *R2000ExecToPod) ProcessEvent(event admission.Attributes, access interface{}) rules.RuleFailure {
	if event == nil {
		return nil
	}

	if event.GetKind().Kind != "PodExecOptions" {
		return nil
	}

	pod, err := unstructuredToPod(event.GetObject().(*unstructured.Unstructured))
	if err != nil {
		return nil
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      rule.Name(),
			FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
			Severity:       R2000ExecToPodRuleDescriptor.Priority,
		},
		AdmissionAlert: apitypes.AdmissionAlert{
			Kind:             event.GetKind(),
			ObjectName:       event.GetName(),
			RequestNamespace: event.GetNamespace(),
			Resource:         event.GetResource(),
			Operation:        event.GetOperation(),
			Object:           event.GetObject().(*unstructured.Unstructured),
			Subresource:      event.GetSubresource(),
			UserInfo: &user.DefaultInfo{
				Name:   event.GetUserInfo().GetName(),
				UID:    event.GetUserInfo().GetUID(),
				Groups: event.GetUserInfo().GetGroups(),
				Extra:  event.GetUserInfo().GetExtra(),
			},

			DryRun:    event.IsDryRun(),
			Options:   event.GetOperationOptions().(*unstructured.Unstructured),
			OldObject: event.GetOldObject().(*unstructured.Unstructured),
		},
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Exec to pod detected on pod %s", pod.Name),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   pod.Name,
			Namespace: pod.Namespace,
		},
		RuleID: R2000ID,
	}

	return &ruleFailure
}

func unstructuredToPod(obj *unstructured.Unstructured) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, pod); err != nil {
		return nil, err
	}
	return pod, nil

}
