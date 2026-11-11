package sbomexport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/pager"
)

// sbomMeta is what the exporter needs to know about an SBOMSyft without its
// document.
type sbomMeta struct {
	namespace, name string
	digest          string
	imageTag        string
	status          string
	created         time.Time
	size            int64 // bytes, from the kubescape.io/resource-size annotation; 0 when unknown
	// toolVersion is the node-agent version that built the SBOM. node-agent
	// rebuilds the SBOM of a running image when its version changes and
	// replaces the document in place, so the creation time stays the same.
	toolVersion string
}

// ready reports whether the SBOM is complete: the statuses the operator's
// image scans accept too (empty for SBOMs written before the annotation).
func (m sbomMeta) ready() bool {
	switch m.status {
	case "", helpersv1.Learning, helpersv1.Completed:
		return true
	}
	return false
}

// metaOf reads sbomMeta from an SBOMSyft's metadata. It reports false when
// the object names no image.
func metaOf(obj *spdxv1beta1.SBOMSyft) (sbomMeta, bool) {
	ann := obj.GetAnnotations()
	imageID, imageTag := ann[helpersv1.ImageIDMetadataKey], ann[helpersv1.ImageTagMetadataKey]
	if imageID == "" || imageTag == "" {
		return sbomMeta{}, false
	}
	size, _ := strconv.ParseInt(ann[helpersv1.ResourceSizeMetadataKey], 10, 64)
	return sbomMeta{
		size:        size,
		namespace:   obj.GetNamespace(),
		name:        obj.GetName(),
		digest:      digestOf(imageID),
		imageTag:    imageTag,
		status:      ann[helpersv1.StatusMetadataKey],
		created:     obj.GetCreationTimestamp().Time,
		toolVersion: ann[helpersv1.ToolVersionMetadataKey],
	}, true
}

// sbomStore reads SBOMSyft objects.
type sbomStore interface {
	// listSBOMs returns the metadata of every SBOMSyft.
	listSBOMs(ctx context.Context) ([]sbomMeta, error)
	// syftDocument returns the `.spec.syft` of one SBOMSyft as JSON. It reads
	// at most limit bytes of the object and returns a *tooLargeError past that.
	syftDocument(ctx context.Context, namespace, name string, limit int64) ([]byte, error)
}

// tooLargeError is an SBOMSyft object larger than the limit it was read with.
type tooLargeError struct {
	read int64 // bytes read before the limit stopped the read
}

// Error says how much of the object was read.
func (e *tooLargeError) Error() string {
	return fmt.Sprintf("SBOMSyft object is larger than the %d bytes read", e.read)
}

// storageSBOMs reads SBOMSyft objects from Kubescape's storage.
type storageSBOMs struct {
	client kssc.Interface
}

// listSBOMs pages through every SBOMSyft and keeps the ones metaOf accepts.
func (s storageSBOMs) listSBOMs(ctx context.Context) ([]sbomMeta, error) {
	var out []sbomMeta
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return s.client.SpdxV1beta1().SBOMSyfts("").List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		if m, ok := metaOf(obj.(*spdxv1beta1.SBOMSyft)); ok {
			out = append(out, m)
		}
		return nil
	})
	return out, err
}

// syftDocument GETs the object as raw JSON rather than through the typed
// client: the document goes to syft's own decoder, and the storage types this
// module builds against may lack fields that a newer node-agent writes. The
// operator's storage client asks for protobuf, so this request asks for JSON.
// The response is read up to limit, so an object without a size annotation
// cannot make the operator buffer more than that.
func (s storageSBOMs) syftDocument(ctx context.Context, namespace, name string, limit int64) ([]byte, error) {
	body, err := s.client.SpdxV1beta1().RESTClient().Get().
		Namespace(namespace).Resource("sbomsyfts").Name(name).
		SetHeader("Accept", "application/json").
		Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("get SBOMSyft %s/%s: %w", namespace, name, err)
	}
	defer func() { _ = body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read SBOMSyft %s/%s: %w", namespace, name, err)
	}
	if int64(len(raw)) > limit {
		return nil, &tooLargeError{read: int64(len(raw))}
	}
	var obj struct {
		Spec struct {
			Syft json.RawMessage `json:"syft"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("decode SBOMSyft %s/%s: %w", namespace, name, err)
	}
	if len(obj.Spec.Syft) == 0 {
		return nil, fmt.Errorf("SBOMSyft %s/%s has no syft document", namespace, name)
	}
	return obj.Spec.Syft, nil
}
