package notificationhandler

import (
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
)

var mockCommandRunKubescapeJob = `{"commands":[{"CommandName":"runKubescapeJob","responseID":"","jobTracking":{"jobID":"6be09aad-a376-4d6b-97ad-8d1a75fce89d","timestamp":"0001-01-01T00:00:00Z"},"args":{"kubescapeJobParams":{"clusterName":"dwertent","frameworkName":"DevOpsBest","jobID":"6be09aad-a376-4d6b-97ad-8d1a75fce89d"},"scanV1":{"targetNames":["DevOpsBest"],"targetType":"Framework"}},"designators":[{"designatorType":"","attributes":{"cluster":"dwertent"}}]}]}`

func TestParseNotificationCommand(t *testing.T) {
	cmd, err := parseNotificationCommand([]byte(mockCommandRunKubescapeJob))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(cmd.Commands))
	assert.Equal(t, apis.TypeRunKubescapeJob, cmd.Commands[0].CommandName)
}
