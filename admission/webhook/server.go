package webhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/watcher"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
)

type AdmissionWebhookInterface interface {
	// Runs the webhook server until the passed context is cancelled, or it
	// experiences an internal error.
	//
	// Error is always non-nil and will always be one of:
	//		deadline exceeded
	//		context cancelled
	//		or http listen error
	Run(ctx context.Context) error
}

type webhook struct {
	validator        admission.ValidationInterface
	objectInferfaces admission.ObjectInterfaces
	decoder          runtime.Decoder
	addr             string
	certFile         string
	keyFile          string
	watcher          watcher.Watcher
}

func New(addr string, certFile, keyFile string, scheme *runtime.Scheme, validator admission.ValidationInterface, watcher watcher.Watcher) AdmissionWebhookInterface {
	codecs := serializer.NewCodecFactory(scheme)
	return &webhook{
		objectInferfaces: admission.NewObjectInterfacesFromScheme(scheme),
		decoder:          codecs.UniversalDeserializer(),
		validator:        validator,
		addr:             addr,
		certFile:         certFile,
		keyFile:          keyFile,
		watcher:          watcher,
	}
}

// certificateSnapshot follows symlink targets, including Kubernetes Secret
// volumes whose ..data link is replaced on rotation. In-place rewrites that
// preserve identity, size and modification time cannot be detected this way.
type certificateSnapshot struct {
	cert os.FileInfo
	key  os.FileInfo
}

func (s certificateSnapshot) equal(other certificateSnapshot) bool {
	same := func(a, b os.FileInfo) bool {
		return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
	}
	return same(s.cert, other.cert) && same(s.key, other.key)
}

type certificateCache struct {
	mu                sync.Mutex
	certFile, keyFile string
	loadKeyPair       func(string, string) (tls.Certificate, error)
	certificate       *tls.Certificate
	snapshot          certificateSnapshot
	lastWarning       string
}

func newCertificateCache(certFile, keyFile string, loadKeyPair func(string, string) (tls.Certificate, error)) (*certificateCache, error) {
	if loadKeyPair == nil {
		loadKeyPair = tls.LoadX509KeyPair
	}
	cache := &certificateCache{certFile: certFile, keyFile: keyFile, loadKeyPair: loadKeyPair}
	// Use the same consistency checks at startup, before the cache is shared.
	if err := cache.reloadIfChanged(); err != nil {
		return nil, err
	}
	return cache, nil
}

func (c *certificateCache) stat() (certificateSnapshot, error) {
	cert, err := os.Stat(c.certFile)
	if err != nil {
		return certificateSnapshot{}, err
	}
	key, err := os.Stat(c.keyFile)
	if err != nil {
		return certificateSnapshot{}, err
	}
	return certificateSnapshot{cert: cert, key: key}, nil
}

// reloadIfChanged makes one attempt. Its caller holds mu once the cache is
// shared; both the certificate and metadata are published together. Neither
// is updated if the files change while loading or the pair cannot be parsed.
func (c *certificateCache) reloadIfChanged() error {
	before, err := c.stat()
	if err != nil {
		return err
	}
	if c.certificate != nil && c.snapshot.equal(before) {
		return nil
	}
	cert, err := c.loadKeyPair(c.certFile, c.keyFile)
	if err != nil {
		return err
	}
	after, err := c.stat()
	if err != nil {
		return err
	}
	if !before.equal(after) {
		return errors.New("TLS files changed while loading the key pair")
	}
	c.certificate = &cert
	c.snapshot = after
	return nil
}

func (c *certificateCache) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.reloadIfChanged(); err != nil {
		// Diagnostic state is separate from the last successful snapshot. In
		// particular, a failed attempt must remain retryable on the next handshake.
		if message := err.Error(); message != c.lastWarning {
			logger.L().Warning("TLS reload failed, keeping the current certificate", helpers.Error(err))
			c.lastWarning = message
		}
	} else {
		c.lastWarning = ""
	}
	// Construction requires a valid initial pair. Reload errors never turn a
	// working cached certificate into a handshake failure.
	return c.certificate, nil
}

// newServer bounds what a peer can hold: the API server sends one review per request
// and waits for the answer, so a request that takes longer than this to arrive or to
// be answered is a stalled connection, and no review needs a larger header.
func newServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func (wh *webhook) Run(ctx context.Context) error {
	logger.L().Info("starting webhook HTTP server")
	defer logger.L().Info("stopping webhook HTTP server")

	cache, err := newCertificateCache(wh.certFile, wh.keyFile, nil)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", wh.handleHealth)
	mux.HandleFunc("/validate", wh.handleWebhookValidate)
	// Leave Certificates empty so clients without SNI also use the callback.
	srv := newServer(wh.addr, mux, &tls.Config{GetCertificate: cache.getCertificate})
	// A buffered result lets the serving goroutine exit during cancellation.
	errChan := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		errChan <- srv.ListenAndServeTLS("", "")
	}()
	defer wg.Wait()

	select {
	case <-ctx.Done():
		if err := srv.Close(); err != nil {
			logger.L().Error("error closing server", helpers.Error(err))
		}
		return ctx.Err()
	case err := <-errChan:
		return err
	}
}

func (wh *webhook) handleHealth(w http.ResponseWriter, req *http.Request) {
	fmt.Fprint(w, "OK")
}

func (wh *webhook) handleWebhookValidate(w http.ResponseWriter, req *http.Request) {
	// The body is read in full before it is parsed, so it is bounded first: an
	// AdmissionReview carries at most the API server's own object size limit, and the
	// listener answers anyone who can reach it, not only the API server.
	req.Body = http.MaxBytesReader(w, req.Body, maxAdmissionReviewBytes)
	parsed, err := parseRequest(req)
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, err.Error(), status)
		return
	}

	failure := func(err error, status int) {
		http.Error(w, err.Error(), status)
		logger.L().Error("review response", helpers.String("uid", string(parsed.Request.UID)), helpers.Int("status", status), helpers.Error(err))
	}

	err = nil

	var attrs admission.Attributes

	if wh.validator.Handles(admission.Operation(parsed.Request.Operation)) {
		var object runtime.Object
		var oldObject runtime.Object

		if len(parsed.Request.OldObject.Raw) > 0 {
			obj, gvk, err := wh.decoder.Decode(parsed.Request.OldObject.Raw, nil, nil)
			switch {
			case gvk == nil || *gvk != schema.GroupVersionKind(parsed.Request.Kind):
				// GVK case first. If object type is unknown it is parsed to
				// unstructured, but
				failure(fmt.Errorf("unexpected GVK %v. Expected %v", gvk, parsed.Request.Kind), http.StatusBadRequest)
				return
			case err != nil && runtime.IsNotRegisteredError(err):
				var oldUnstructured unstructured.Unstructured
				err = json.Unmarshal(parsed.Request.OldObject.Raw, &oldUnstructured)
				if err != nil {
					failure(err, http.StatusInternalServerError)
					return
				}

				oldObject = &oldUnstructured
			case err != nil:
				failure(err, http.StatusBadRequest)
				return
			default:
				oldObject = obj
			}
		}

		if len(parsed.Request.Object.Raw) > 0 {
			obj, gvk, err := wh.decoder.Decode(parsed.Request.Object.Raw, nil, nil)
			switch {
			case gvk == nil || *gvk != schema.GroupVersionKind(parsed.Request.Kind):
				// GVK case first. If object type is unknown it is parsed to
				// unstructured, but
				failure(fmt.Errorf("unexpected GVK %v. Expected %v", gvk, parsed.Request.Kind), http.StatusBadRequest)
				return
			case err != nil && runtime.IsNotRegisteredError(err):
				var objUnstructured unstructured.Unstructured
				err = json.Unmarshal(parsed.Request.Object.Raw, &objUnstructured)
				if err != nil {
					failure(err, http.StatusInternalServerError)
					return
				}

				object = &objUnstructured
			case err != nil:
				failure(err, http.StatusBadRequest)
				return
			default:
				object = obj
			}
		}

		// Parse into native types if possible
		convertExtra := func(input map[string]authenticationv1.ExtraValue) map[string][]string {
			if input == nil {
				return nil
			}

			res := map[string][]string{}
			for k, v := range input {
				var converted []string
				for _, s := range v {
					converted = append(converted, string(s))
				}
				res[k] = converted
			}
			return res
		}

		//!TODO: Parse options as v1.CreateOptions, v1.DeleteOptions, or v1.PatchOptions

		attrs = admission.NewAttributesRecord(
			object,
			oldObject,
			schema.GroupVersionKind(parsed.Request.Kind),
			parsed.Request.Namespace,
			parsed.Request.Name,
			schema.GroupVersionResource{
				Group:    parsed.Request.Resource.Group,
				Version:  parsed.Request.Resource.Version,
				Resource: parsed.Request.Resource.Resource,
			},
			parsed.Request.SubResource,
			admission.Operation(parsed.Request.Operation),
			nil, // operation options?
			false,
			&user.DefaultInfo{
				Name:   parsed.Request.UserInfo.Username,
				UID:    parsed.Request.UserInfo.UID,
				Groups: parsed.Request.UserInfo.Groups,
				Extra:  convertExtra(parsed.Request.UserInfo.Extra),
			})

		err = wh.validator.Validate(context.TODO(), attrs, wh.objectInferfaces)
	}

	response := wh.reviewResponse(
		parsed.Request.UID,
		err,
		attrs,
	)

	out, err := json.Marshal(response)
	if err != nil {
		failure(err, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func (wh *webhook) reviewResponse(uid types.UID, err error, attrs admission.Attributes) *admissionv1.AdmissionReview {
	var status int32 = http.StatusAccepted
	if err != nil {
		status = http.StatusForbidden
	}
	reason := metav1.StatusReasonUnknown
	message := "valid"
	if err != nil {
		message = err.Error()
	}

	var statusErr *k8serrors.StatusError
	if ok := errors.As(err, &statusErr); ok {
		reason = statusErr.ErrStatus.Reason
		message = statusErr.ErrStatus.Message
		status = statusErr.ErrStatus.Code
	}

	// If the request is denied, we want to log the request and the reason for the denial. (denied == allowed but we want to audit).
	if status != http.StatusAccepted {
		logger.L().Debug("admission audit", helpers.Error(err), helpers.Interface("attrs", attrs))
	}

	// We don't want to deny the requests.
	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AdmissionReview",
			APIVersion: "admission.k8s.io/v1",
		},
		Response: &admissionv1.AdmissionResponse{
			UID:     uid,
			Allowed: true,
			Result: &metav1.Status{
				Code:    http.StatusAccepted,
				Message: message,
				Reason:  reason,
			},
		},
	}
}

// maxAdmissionReviewBytes bounds a review's body: the API server refuses objects over
// 3 MiB, so a review is smaller than that plus its envelope.
const maxAdmissionReviewBytes = 4 << 20

// parseRequest extracts an AdmissionReview from an http.Request if possible
func parseRequest(r *http.Request) (*admissionv1.AdmissionReview, error) {
	if r.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("Content-Type: %q should be %q",
			r.Header.Get("Content-Type"), "application/json")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read admission review request: %w", err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("admission request body is empty")
	}

	var admissionReview admissionv1.AdmissionReview

	if err := json.Unmarshal(body, &admissionReview); err != nil {
		return nil, fmt.Errorf("could not parse admission review request: %w", err)
	}

	if admissionReview.Request == nil {
		return nil, fmt.Errorf("admission review can't be used: Request field is nil")
	}

	return &admissionReview, nil
}
