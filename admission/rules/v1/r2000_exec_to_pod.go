package rules

import (
	"fmt"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/admission/rules"
	"github.com/kubescape/operator/objectcache"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
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
	Priority:    RulePriorityLow,
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

func (rule *R2000ExecToPod) ProcessEvent(event admission.Attributes, access objectcache.KubernetesCache) rules.RuleFailure {
	if event == nil {
		return nil
	}

	if event.GetKind().Kind != "PodExecOptions" {
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

	client := access.GetClientset()

	workloadKind, workloadName, workloadNamespace, nodeName, err := GetControllerDetails(event, client)
	if err != nil {
		logger.L().Error("Failed to get parent workload details", helpers.Error(err))
		return nil
	}

	containerName, err := GetContainerNameFromExecToPodEvent(event)
	if err != nil {
		logger.L().Error("Failed to get container name from exec to pod event", helpers.Error(err))
		containerName = ""
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      rule.Name(),
			FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
			Severity:       R2000ExecToPodRuleDescriptor.Priority,
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
			RuleDescription: fmt.Sprintf("Exec to pod detected on pod %s", event.GetName()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:           event.GetName(),
			PodNamespace:      event.GetNamespace(),
			Namespace:         event.GetNamespace(),
			WorkloadName:      workloadName,
			WorkloadNamespace: workloadNamespace,
			WorkloadKind:      workloadKind,
			NodeName:          nodeName,
			ContainerName:     containerName,
		},
		RuleID: R2000ID,
	}

	return &ruleFailure
}
