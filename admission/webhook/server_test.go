package webhook

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/admission"
)

// MockValidator is a mock implementation of the admission.ValidationInterface for testing purposes
type MockValidator struct{}

func (v *MockValidator) Handles(o admission.Operation) bool {
	return true
}

func (v *MockValidator) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	return nil
}

func TestHandleHealth(t *testing.T) {
	wh := &webhook{}
	req := httptest.NewRequest("GET", "http://localhost/health", nil)
	w := httptest.NewRecorder()

	wh.handleHealth(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, "OK", string(body))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandleWebhookValidate(t *testing.T) {
	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)
	decoder := codecs.UniversalDeserializer()

	wh := &webhook{
		validator:        &MockValidator{},
		objectInferfaces: admission.NewObjectInterfacesFromScheme(scheme),
		decoder:          decoder,
	}

	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:  "12345",
			Kind: metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
			Object: runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"test"}}`),
			},
		},
	}
	reviewBytes, _ := json.Marshal(review)
	req := httptest.NewRequest("POST", "http://localhost/validate", bytes.NewReader(reviewBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	wh.handleWebhookValidate(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var admissionReview admissionv1.AdmissionReview
	err := json.Unmarshal(body, &admissionReview)
	assert.NoError(t, err)
	assert.Equal(t, review.Request.UID, admissionReview.Response.UID)
	assert.True(t, admissionReview.Response.Allowed)
}

func TestRun(t *testing.T) {
	admissionController := New(":8443", "testdata/cert.pem", "testdata/key.pem", runtime.NewScheme(), &MockValidator{}, watcher.NewWatcherMock())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	errChan := make(chan error)
	go func() {
		errChan <- admissionController.Run(ctx)
	}()

	// Allow more time for the server to start
	time.Sleep(5 * time.Second)

	// Make a health check request
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get("https://localhost:8443/health")
	if err != nil {
		t.Fatalf("failed to get health check: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "OK", string(body))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Cancel the context to stop the server
	cancel()

	// Wait for the server to shut down
	select {
	case err := <-errChan:
		if err != nil && err != http.ErrServerClosed && err != context.Canceled {
			t.Fatalf("Run method returned error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down in time")
	default:
		return
	}
}

func TestParseRequest_ContentType(t *testing.T) {
	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID: "12345",
		},
	}
	body, _ := json.Marshal(review)

	tests := []struct {
		name        string
		contentType string
		wantErr     bool
	}{
		{
			name:        "exact application/json",
			contentType: "application/json",
			wantErr:     false,
		},
		{
			name:        "application/json with charset utf-8",
			contentType: "application/json; charset=utf-8",
			wantErr:     false,
		},
		{
			name:        "application/json case insensitive with spaces and params",
			contentType: "APPLICATION/JSON; charset=UTF-8",
			wantErr:     false,
		},
		{
			name:        "text/plain rejected",
			contentType: "text/plain",
			wantErr:     true,
		},
		{
			name:        "application/xml rejected",
			contentType: "application/xml",
			wantErr:     true,
		},
		{
			name:        "empty content-type rejected",
			contentType: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "http://localhost/validate", bytes.NewReader(body))
			req.Header.Set("Content-Type", tt.contentType)
			res, err := parseRequest(req)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, res)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, res)
			}
		})
	}
}

func TestHandleWebhookValidate_ContentType(t *testing.T) {
	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)
	decoder := codecs.UniversalDeserializer()

	wh := &webhook{
		validator:        &MockValidator{},
		objectInferfaces: admission.NewObjectInterfacesFromScheme(scheme),
		decoder:          decoder,
	}

	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:  "12345",
			Kind: metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
			Object: runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"test"}}`),
			},
		},
	}
	reviewBytes, _ := json.Marshal(review)

	t.Run("succeeds with media type parameters", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://localhost/validate", bytes.NewReader(reviewBytes))
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		w := httptest.NewRecorder()

		wh.handleWebhookValidate(w, req)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("fails with non-json content type", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://localhost/validate", bytes.NewReader(reviewBytes))
		req.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		wh.handleWebhookValidate(w, req)
		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

type contextTrackingValidator struct {
	MockValidator
	receivedCtx context.Context
}

func (v *contextTrackingValidator) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	v.receivedCtx = ctx
	return ctx.Err()
}

func TestHandleWebhookValidate_ContextPropagation(t *testing.T) {
	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)
	decoder := codecs.UniversalDeserializer()

	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:  "12345",
			Kind: metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
			Object: runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"test"}}`),
			},
		},
	}
	reviewBytes, _ := json.Marshal(review)

	t.Run("propagates active context with custom key", func(t *testing.T) {
		val := &contextTrackingValidator{}
		wh := &webhook{
			validator:        val,
			objectInferfaces: admission.NewObjectInterfacesFromScheme(scheme),
			decoder:          decoder,
		}

		type ctxKey string
		const testKey ctxKey = "test-key"
		ctx := context.WithValue(context.Background(), testKey, "custom-value")

		req := httptest.NewRequest("POST", "http://localhost/validate", bytes.NewReader(reviewBytes)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		wh.handleWebhookValidate(w, req)

		assert.NotNil(t, val.receivedCtx)
		assert.Equal(t, "custom-value", val.receivedCtx.Value(testKey))
		assert.NoError(t, val.receivedCtx.Err())
	})

	t.Run("propagates cancelled context and reflects error", func(t *testing.T) {
		val := &contextTrackingValidator{}
		wh := &webhook{
			validator:        val,
			objectInferfaces: admission.NewObjectInterfacesFromScheme(scheme),
			decoder:          decoder,
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		req := httptest.NewRequest("POST", "http://localhost/validate", bytes.NewReader(reviewBytes)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		wh.handleWebhookValidate(w, req)

		assert.NotNil(t, val.receivedCtx)
		assert.Equal(t, context.Canceled, val.receivedCtx.Err())

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		var admissionReview admissionv1.AdmissionReview
		err := json.Unmarshal(body, &admissionReview)
		assert.NoError(t, err)
		assert.Equal(t, context.Canceled.Error(), admissionReview.Response.Result.Message)
	})
}
