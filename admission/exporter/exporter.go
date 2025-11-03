package exporters

import (
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/operator/admission/rules"
)

type Exporter interface {
	SendAdmissionAlert(ruleFailure rules.RuleFailure)
	SendRegistryStatus(guid string, status armotypes.RegistryScanStatus, statusMessage string, time time.Time)
}
