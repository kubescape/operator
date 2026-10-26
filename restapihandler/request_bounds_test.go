package restapihandler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestActionRequestRefusesABodyOverTheBound(t *testing.T) {
	handler := &HTTPHandler{}
	body := bytes.Repeat([]byte("a"), maxTriggerRequestBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/triggerAction", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ActionRequest(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Result().StatusCode)
}

func TestNewServerBoundsWhatAClientCanHold(t *testing.T) {
	handler := http.NewServeMux()

	srv := newServer(":4002", handler)

	assert.Equal(t, ":4002", srv.Addr)
	assert.Same(t, handler, srv.Handler)
	assert.Positive(t, srv.ReadHeaderTimeout)
	assert.Positive(t, srv.ReadTimeout)
	assert.Positive(t, srv.WriteTimeout)
	assert.Positive(t, srv.IdleTimeout)
	assert.Positive(t, srv.MaxHeaderBytes)
}
