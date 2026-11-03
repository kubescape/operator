package restapihandler

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/go-logr/stdr"
	"github.com/kubescape/storage/pkg/apiauth"
	"k8s.io/client-go/kubernetes"
)

// triggerActionPath is the protected trigger route.
const triggerActionPath = "/v1/triggerAction"

const defaultAPIAudience = "kubescape.io"

// apiAuthRoute maps a request to the permission it requires; the trigger path is protected for every method.
func apiAuthRoute(r *http.Request) (apiauth.Attributes, bool) {
	if r.URL.Path == triggerActionPath {
		return apiauth.Attributes{Group: "kubescape.io", Resource: "operatorcommands", Verb: "create"}, true
	}
	return apiauth.Attributes{}, false
}

// NewAPIAuth builds the authentication middleware for the operator's HTTP API.
// KS_API_AUDIENCE overrides the token audience; POD_NAMESPACE is the SAR namespace.
func NewAPIAuth(ctx context.Context, client kubernetes.Interface) (func(http.Handler) http.Handler, error) {
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" && os.Getenv(apiauth.DisabledEnv) != "true" {
		return nil, errors.New("POD_NAMESPACE must be set for API auth (or set " + apiauth.DisabledEnv + "=true)")
	}
	audience := os.Getenv("KS_API_AUDIENCE")
	if audience == "" {
		audience = defaultAPIAudience
	}
	return apiauth.New(ctx, apiauth.Config{
		Client:    client,
		Audience:  audience,
		Namespace: namespace,
		Route:     apiAuthRoute,
		Logger:    stdr.New(log.New(os.Stderr, "apiauth: ", log.LstdFlags)),
	})
}
