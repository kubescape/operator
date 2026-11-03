package restapihandler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubescape/operator/docs"
	"github.com/kubescape/storage/pkg/apiauth"
)

func TestApiAuthRoute(t *testing.T) {
	attrs, ok := apiAuthRoute(httptest.NewRequest(http.MethodPost, "/v1/triggerAction", nil))
	if !ok {
		t.Fatal("POST /v1/triggerAction must be protected")
	}
	want := apiauth.Attributes{Group: "kubescape.io", Resource: "operatorcommands", Verb: "create"}
	if attrs != want {
		t.Fatalf("attributes = %+v, want %+v", attrs, want)
	}

	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if attrs, ok := apiAuthRoute(httptest.NewRequest(m, "/v1/triggerAction", nil)); !ok || attrs != want {
			t.Fatalf("%s /v1/triggerAction must be protected, got %+v %v", m, attrs, ok)
		}
	}

	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, docs.OpenAPIV2Prefix, nil),
		httptest.NewRequest(http.MethodPost, "/other", nil),
	} {
		if attrs, ok := apiAuthRoute(r); ok || attrs != (apiauth.Attributes{}) {
			t.Fatalf("%s %s must not be protected, got %+v %v", r.Method, r.URL.Path, attrs, ok)
		}
	}
}

func TestSetupHTTPListener_TriggerRequiresAuth(t *testing.T) {
	deny := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	}
	h := NewHTTPHandler(nil, nil).router(deny)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/triggerAction", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("trigger status = %d, want 401", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, docs.OpenAPIV2Prefix, nil))
	if rec.Code == http.StatusUnauthorized {
		t.Fatal("OpenAPI UI must not be behind auth")
	}
}

func TestNewAPIAuth_RequiresPodNamespace(t *testing.T) {
	t.Setenv(apiauth.DisabledEnv, "")
	t.Setenv("POD_NAMESPACE", "")
	if _, err := NewAPIAuth(context.Background(), nil); err == nil {
		t.Fatal("expected an error when POD_NAMESPACE is empty")
	}
}
