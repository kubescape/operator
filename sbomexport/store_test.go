package sbomexport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// The operator's storage client asks for protobuf (main.go). The SBOM document
// is read as JSON for syft's decoder, so that one request must ask for JSON.
func TestStorageSBOMsReadsTheSyftDocumentAsJSONFromAProtobufClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces/kubescape/sbomsyfts/nginx-sbom" {
			http.NotFound(w, r)
			return
		}
		if !strings.Contains(r.Header.Get("Accept"), "application/json") {
			w.Header().Set("Content-Type", "application/vnd.kubernetes.protobuf")
			_, _ = w.Write([]byte("k8s\x00\x0a\x0f"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiVersion":"spdx.softwarecomposition.kubescape.io/v1beta1","kind":"SBOMSyft","spec":{"syft":` + string(curlSyftJSON) + `}}`))
	}))
	defer srv.Close()
	client, err := kssc.NewForConfig(&rest.Config{
		Host: srv.URL,
		ContentConfig: rest.ContentConfig{
			AcceptContentTypes: "application/vnd.kubernetes.protobuf",
			ContentType:        "application/vnd.kubernetes.protobuf",
		},
	})
	require.NoError(t, err)

	doc, err := storageSBOMs{client: client}.syftDocument(context.Background(), "kubescape", "nginx-sbom", 1<<20)

	require.NoError(t, err)
	assert.JSONEq(t, string(curlSyftJSON), string(doc))
	_, err = toCycloneDX(doc)
	assert.NoError(t, err)
}

// An object without a size annotation is read only up to the limit.
func TestStorageSBOMsStopsReadingAnObjectLargerThanTheLimit(t *testing.T) {
	big := `{"spec":{"syft":{"artifacts":[` + strings.Repeat(`{"name":"pkg"},`, 200_000) + `{}]}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()
	client, err := kssc.NewForConfig(&rest.Config{Host: srv.URL})
	require.NoError(t, err)

	_, err = storageSBOMs{client: client}.syftDocument(context.Background(), "kubescape", "big-sbom", 1<<20)

	var tooLarge *tooLargeError
	require.ErrorAs(t, err, &tooLarge)
	assert.Equal(t, int64(1<<20+1), tooLarge.read)
	assert.Greater(t, len(big), 1<<20)
}
