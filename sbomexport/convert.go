package sbomexport

import (
	"bytes"
	"fmt"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/syftjson"
)

// cycloneDXVersion is the CycloneDX specification version of the uploaded
// BOMs.
const cycloneDXVersion = "1.6"

// toCycloneDX converts a syft JSON document, the `.spec.syft` of an SBOMSyft,
// to CycloneDX JSON, the way `syft convert` does: syft's own syft-json
// decoder, then its CycloneDX encoder.
func toCycloneDX(syftJSON []byte) ([]byte, error) {
	s, _, _, err := syftjson.NewFormatDecoder().Decode(bytes.NewReader(syftJSON))
	if err != nil {
		return nil, fmt.Errorf("decode syft document: %w", err)
	}
	enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.EncoderConfig{Version: cycloneDXVersion})
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := enc.Encode(&buf, *s); err != nil {
		return nil, fmt.Errorf("encode CycloneDX: %w", err)
	}
	return buf.Bytes(), nil
}
