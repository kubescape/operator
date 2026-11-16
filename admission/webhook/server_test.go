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
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

type capturingValidator struct {
	attrs admission.Attributes
}

func (v *capturingValidator) Handles(o admission.Operation) bool {
	return true
}

func (v *capturingValidator) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	v.attrs = a
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

func TestHandleWebhookValidate_DryRunAndOptions(t *testing.T) {
	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)
	decoder := codecs.UniversalDeserializer()

	captor := &capturingValidator{}
	wh := &webhook{
		validator:        captor,
		objectInferfaces: admission.NewObjectInterfacesFromScheme(scheme),
		decoder:          decoder,
	}

	dryRun := true
	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:    "12345",
			Kind:   metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
			DryRun: &dryRun,
			Options: runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"meta.k8s.io/v1","kind":"CreateOptions","dryRun":["All"]}`),
			},
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
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotNil(t, captor.attrs, "validator should receive attributes")
	assert.True(t, captor.attrs.IsDryRun(), "attributes should preserve DryRun=true from AdmissionRequest")
	assert.NotNil(t, captor.attrs.GetOperationOptions(), "attributes should preserve operation options from AdmissionRequest")
}

func TestHandleWebhookValidate_TypedObject(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, appsv1.AddToScheme(scheme))
	codecs := serializer.NewCodecFactory(scheme)
	decoder := codecs.UniversalDeserializer()

	captor := &capturingValidator{}
	wh := &webhook{
		validator:        captor,
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
			OldObject: runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"test-old"}}`),
			},
		},
	}
	reviewBytes, _ := json.Marshal(review)
	req := httptest.NewRequest("POST", "http://localhost/validate", bytes.NewReader(reviewBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	wh.handleWebhookValidate(w, req)

	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotNil(t, captor.attrs)
	_, isUnstructuredObj := captor.attrs.GetObject().(*unstructured.Unstructured)
	assert.True(t, isUnstructuredObj, "object should be converted to *unstructured.Unstructured")
	_, isUnstructuredOld := captor.attrs.GetOldObject().(*unstructured.Unstructured)
	assert.True(t, isUnstructuredOld, "oldObject should be converted to *unstructured.Unstructured")
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
