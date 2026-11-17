package mainhandler

import (
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/validation"
)

func getCommandForConfigMap(jobName, cronTabSchedule string) *apis.Command {
	jobParams := apis.CronJobParams{
		JobName:         jobName,
		CronTabSchedule: cronTabSchedule,
	}
	return &apis.Command{
		CommandName: apis.TypeSetVulnScanCronJob,
		WildWlid:    "wlid://cluster-minikube",
		Args: map[string]interface{}{
			"jobParams": jobParams,
		},
	}
}
func TestGetJobParams(t *testing.T) {
	jobName := "aaaa"
	cronTabSchedule := "bbbb"
	command := getCommandForConfigMap(jobName, cronTabSchedule)
	jobParams := getJobParams(command)

	assert.Equal(t, jobParams.JobName, jobName)
	assert.Equal(t, jobParams.CronTabSchedule, cronTabSchedule)

}

// The random number at the end of a scheduled scan's name keeps two schedules of
// the same framework apart, so a long framework name must not cut it off.
func TestScheduledScanNameKeepsTheRandomSuffix(t *testing.T) {
	assert.Equal(t, "ks-scheduled-scan-nsa-1111111111111111111", scheduledScanName("nsa", 1111111111111111111))

	for _, target := range []string{
		"nsa",
		strings.Repeat("a", 31),
		"My Organization Production Baseline", // a custom framework name
		strings.Repeat("x", 80),
	} {
		t.Run(target, func(t *testing.T) {
			first := scheduledScanName(target, 1111111111111111111)
			second := scheduledScanName(target, 2222222222222222222)

			assert.NotEqual(t, first, second)
			assert.True(t, strings.HasSuffix(first, "-1111111111111111111"), first)
			assert.True(t, strings.HasPrefix(first, "ks-scheduled-scan-"), first)
			assert.LessOrEqual(t, len(first), 52)
			assert.Empty(t, validation.IsDNS1123Label(first))
		})
	}
}
