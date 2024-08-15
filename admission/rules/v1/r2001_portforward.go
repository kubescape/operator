package rules

import (
	"fmt"
	"time"

	"github.com/kubescape/operator/admission/rules"
	"github.com/kubescape/operator/objectcache"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R2001ID   = "R2001"
	R2001Name = "Port forward"
)

var R2001PortForwardRuleDescriptor = RuleDescriptor{
	ID:          R2001ID,
	Name:        R2001Name,
	Description: "Detecting port forward",
	Tags:        []string{"portforward"},
	Priority:    RulePriorityLow,
	RuleCreationFunc: func() rules.RuleEvaluator {
		return CreateRuleR2001PortForward()
	},
}

type R2001PortForward struct {
	BaseRule
}

func CreateRuleR2001PortForward() *R2001PortForward {
	return &R2001PortForward{}
}
func (rule *R2001PortForward) Name() string {
	return R2001Name
}

func (rule *R2001PortForward) ID() string {
	return R2001ID
}

func (rule *R2001PortForward) DeleteRule() {
}

func (rule *R2001PortForward) ProcessEvent(event admission.Attributes, access interface{}) rules.RuleFailure {
	if event == nil {
		return nil
	}

	if event.GetKind().Kind != "PodPortForwardOptions" {
		return nil
	}

	var oldObject *unstructured.Unstructured
	if event.GetOldObject() != nil {
		oldObject = event.GetOldObject().(*unstructured.Unstructured)
	}

	var options *unstructured.Unstructured
	if event.GetOperationOptions() != nil {
		options = event.GetOperationOptions().(*unstructured.Unstructured)
	}

	client := access.(objectcache.KubernetesCache).GetClientset()

	workloadKind, workloadName, workloadNamespace, nodeName, err := GetParentWorkloadDetails(event, client)
	if err != nil {
		zap.L().Error("Failed to get parent workload details", zap.Error(err))
		return nil
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      rule.Name(),
			FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
			Severity:       R2001PortForwardRuleDescriptor.Priority,
			Timestamp:      time.Unix(0, time.Now().UnixNano()),
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
			Options:   options,
			OldObject: oldObject,
		},
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Port forward detected on pod %s", event.GetName()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:      event.GetName(),
			Namespace:    event.GetNamespace(),
			WorkloadName: workloadName,
			WorkloadNamespace: workloadNamespace,
			WorkloadKind: workloadKind,
			NodeName:     nodeName,
		},
		RuleID: R2001ID,
	}

	return &ruleFailure
}
