package restapihandler

import (
	"context"
	"net/http"
	"os"

	"github.com/kubescape/storage/pkg/apiauth"
	"k8s.io/client-go/kubernetes"
)

const defaultAPIAudience = "kubescape.io"

// apiAuthRoute maps a request to the permission it requires; only the trigger route is protected.
func apiAuthRoute(r *http.Request) (apiauth.Attributes, bool) {
	if r.Method == http.MethodPost && r.URL.Path == "/v1/triggerAction" {
		return apiauth.Attributes{Group: "kubescape.io", Resource: "operatorcommands", Verb: "create"}, true
	}
	return apiauth.Attributes{}, false
}

// NewAPIAuth builds the authentication middleware for the operator's HTTP API.
// KS_API_AUDIENCE overrides the token audience; POD_NAMESPACE is the SAR namespace.
func NewAPIAuth(ctx context.Context, client kubernetes.Interface) (func(http.Handler) http.Handler, error) {
	audience := os.Getenv("KS_API_AUDIENCE")
	if audience == "" {
		audience = defaultAPIAudience
	}
	return apiauth.New(ctx, apiauth.Config{
		Client:    client,
		Audience:  audience,
		Namespace: os.Getenv("POD_NAMESPACE"),
		Route:     apiAuthRoute,
	})
}
