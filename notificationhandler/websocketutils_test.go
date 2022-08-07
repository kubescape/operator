package notificationhandler

import (
	_ "embed"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
)

//go:embed testdata/mockCommandRunKubescapeJob.json
var mockCommandRunKubescapeJob string

func TestParseNotificationCommand(t *testing.T) {
	cmd, err := parseNotificationCommand([]byte(mockCommandRunKubescapeJob))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(cmd.Commands))
	assert.Equal(t, apis.TypeRunKubescapeJob, cmd.Commands[0].CommandName)
}
