/*
Package docs documents the HTTP API endpoints.
The documentation is then used to generate an OpenAPI spec.
*/
package docs

import (
	"github.com/armosec/armoapi-go/apis"
)

// swagger:parameters postTriggerAction
type postTriggerActionParams struct {
	// In: body
	Body apis.Commands
}

/*
The server has successfully received the action.

swagger:response postTriggerActionOK
*/
type postTriggerActionOK struct {
	// In: body
	// Example: ok
	Body string
}

/*
swagger:route POST /v1/triggerAction postTriggerAction
Triggers an action to be run in one of the Kubescape in-cluster components.

Responses:
  200: postTriggerActionOK
*/
