package webhook

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// A legitimate UPDATE review carries both objects: ten environment variables of 70 KB
// each give two Pods of 2.4 MB and a review of 4.9 MB, which the API server's 3 MiB
// request limit does not bound and the webhook has to accept.
func TestHandleWebhookValidateAcceptsALargeUpdateReview(t *testing.T) {
	scheme := runtime.NewScheme()
	wh := &webhook{
		validator:        &MockValidator{},
		objectInferfaces: admission.NewObjectInterfacesFromScheme(scheme),
		decoder:          serializer.NewCodecFactory(scheme).UniversalDeserializer(),
	}
	pod := &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: "big", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app"}}},
	}
	for i := 0; i < 10; i++ {
		pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
			Name:  fmt.Sprintf("V%d", i),
			Value: "<root>" + strings.Repeat("<a/>", 17500) + "</root>",
		})
	}
	raw, err := json.Marshal(pod)
	require.NoError(t, err)
	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       "big",
			Operation: admissionv1.Update,
			Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Object:    runtime.RawExtension{Raw: raw},
			OldObject: runtime.RawExtension{Raw: raw},
		},
	}
	reviewBytes, err := json.Marshal(review)
	require.NoError(t, err)
	require.Greater(t, len(reviewBytes), 4<<20)
	require.Less(t, len(reviewBytes), maxAdmissionReviewBytes)
	req := httptest.NewRequest(http.MethodPost, "http://localhost/validate", bytes.NewReader(reviewBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	wh.handleWebhookValidate(w, req)

	require.Equal(t, http.StatusOK, w.Result().StatusCode, w.Body.String())
	var answered admissionv1.AdmissionReview
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &answered))
	assert.True(t, answered.Response.Allowed)
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
