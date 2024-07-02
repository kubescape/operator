package rules

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"k8s.io/apiserver/pkg/admission"
)

const (
	RulePriorityNone        = 0
	RulePriorityLow         = 1
	RulePriorityMed         = 5
	RulePriorityHigh        = 8
	RulePriorityCritical    = 10
	RulePrioritySystemIssue = 1000
)

// RuleCreator is an interface for creating rules by tags, IDs, and names
type RuleCreator interface {
	CreateRulesByTags(tags []string) []RuleEvaluator
	CreateRuleByID(id string) RuleEvaluator
	CreateRuleByName(name string) RuleEvaluator
}

type RuleEvaluator interface {
	// Rule ID - this is the rules unique identifier
	ID() string
	// Rule Name
	Name() string
	// Rule processing
	ProcessEvent(event admission.Attributes, access interface{}) RuleFailure
	// Set rule parameters
	SetParameters(parameters map[string]interface{})
	// Get rule parameters
	GetParameters() map[string]interface{}
}

type RuleFailure interface {
	// Get Base Runtime Alert
	GetBaseRuntimeAlert() apitypes.BaseRuntimeAlert
	// Get Runtime Process Details
	GetRuntimeProcessDetails() apitypes.ProcessTree
	// Get Rule Description
	GetRuleAlert() apitypes.RuleAlert
	// Get Admissions Details
	GetAdmissionsAlert() apitypes.AdmissionAlert
	// Get K8s Runtime Details
	GetRuntimeAlertK8sDetails() apitypes.RuntimeAlertK8sDetails
	// Get Rule ID
	GetRuleId() string

	// Set Workload Details
	SetWorkloadDetails(workloadDetails string)
	// Set Base Runtime Alert
	SetBaseRuntimeAlert(baseRuntimeAlert apitypes.BaseRuntimeAlert)
	// Set Runtime Process Details
	SetRuntimeProcessDetails(runtimeProcessDetails apitypes.ProcessTree)
	// Set Rule Description
	SetRuleAlert(ruleAlert apitypes.RuleAlert)
	// Set Admissions Details
	SetAdmissionsAlert(admissionsAlert apitypes.AdmissionAlert)
	// Set K8s Runtime Details
	SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails apitypes.RuntimeAlertK8sDetails)
}
