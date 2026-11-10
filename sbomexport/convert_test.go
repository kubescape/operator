package sbomexport

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// curl-8.11.1.syft.json is the `.spec.syft` that node-agent v0.3.310 stored
// for docker.io/curlimages/curl:8.11.1; curl-8.11.1.cdx.json is what
// `syft convert -o cyclonedx-json@1.6` (syft v1.55.0) makes of it.
var (
	//go:embed testdata/curl-8.11.1.syft.json
	curlSyftJSON []byte
	//go:embed testdata/curl-8.11.1.cdx.json
	curlCycloneDX []byte
)

func TestToCycloneDXMatchesSyftConvert(t *testing.T) {
	got, err := toCycloneDX(curlSyftJSON)
	require.NoError(t, err)

	var gotBOM, wantBOM map[string]any
	require.NoError(t, json.Unmarshal(got, &gotBOM))
	require.NoError(t, json.Unmarshal(curlCycloneDX, &wantBOM))
	assert.Equal(t, cycloneDXVersion, gotBOM["specVersion"])
	assert.Equal(t, wantBOM["components"], gotBOM["components"])
	assert.Equal(t, wantBOM["dependencies"], gotBOM["dependencies"])
	assert.Equal(t, wantBOM["metadata"].(map[string]any)["component"], gotBOM["metadata"].(map[string]any)["component"])
}

func TestToCycloneDXRejectsADocumentThatIsNotSyftJSON(t *testing.T) {
	_, err := toCycloneDX(curlCycloneDX)
	assert.Error(t, err)
}
