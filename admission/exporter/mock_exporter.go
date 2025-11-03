package exporters

import (
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/operator/admission/rules"
)

type MockExporter struct{}

var _ Exporter = (*MockExporter)(nil)

func (m MockExporter) SendAdmissionAlert(_ rules.RuleFailure) {}

func (m MockExporter) SendRegistryStatus(_ string, _ armotypes.RegistryScanStatus, _ string, _ time.Time) {
}
