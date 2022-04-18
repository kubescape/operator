package mainhandler

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/armosec/armoapi-go/apis"
)

func TestKubescapeV1ScanURL(t *testing.T) {
	assert.Equal(t, "http://kubescape:8080/v1/scan", kubescapeV1ScanURL().String())
}

func TestGetKubescapeV1ScanRequest(t *testing.T) {
	{
		actionHandler := ActionHandler{
			command: apis.Command{
				Args: map[string]interface{}{
					"v1/scan": nil,
				},
			},
		}
		req, err := getKubescapeV1ScanRequest(actionHandler.command.Args)
		assert.NoError(t, err)
		assert.NotEqual(t, 0, len(req))
	}
	{
		actionHandler := ActionHandler{
			command: apis.Command{Args: map[string]interface{}{"v1/scan": map[string]interface{}{"format": "json"}}},
		}
		req, err := getKubescapeV1ScanRequest(actionHandler.command.Args)
		assert.NoError(t, err)
		assert.NotEqual(t, 0, len(req))
	}
}
