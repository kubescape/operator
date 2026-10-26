package webhook

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/admission"
)

func TestHandleWebhookValidateRefusesABodyOverTheBound(t *testing.T) {
	scheme := runtime.NewScheme()
	wh := &webhook{
		validator:        &MockValidator{},
		objectInferfaces: admission.NewObjectInterfacesFromScheme(scheme),
		decoder:          serializer.NewCodecFactory(scheme).UniversalDeserializer(),
	}
	body := bytes.Repeat([]byte("a"), maxAdmissionReviewBytes+1)
	req := httptest.NewRequest(http.MethodPost, "http://localhost/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	wh.handleWebhookValidate(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Result().StatusCode)
}

func TestNewServerBoundsWhatAPeerCanHold(t *testing.T) {
	handler := http.NewServeMux()
	tlsConfig := &tls.Config{}

	srv := newServer(":8443", handler, tlsConfig)

	assert.Equal(t, ":8443", srv.Addr)
	assert.Same(t, handler, srv.Handler)
	assert.Same(t, tlsConfig, srv.TLSConfig)
	assert.Positive(t, srv.ReadHeaderTimeout)
	assert.Positive(t, srv.ReadTimeout)
	assert.Positive(t, srv.WriteTimeout)
	assert.Positive(t, srv.IdleTimeout)
	assert.Positive(t, srv.MaxHeaderBytes)
}
