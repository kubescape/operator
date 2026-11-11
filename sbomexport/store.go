package sbomexport

import (
	"context"
	"encoding/json"
	"fmt"
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
		size:      size,
		namespace: obj.GetNamespace(),
		name:      obj.GetName(),
		digest:    digestOf(imageID),
		imageTag:  imageTag,
		status:    ann[helpersv1.StatusMetadataKey],
		created:   obj.GetCreationTimestamp().Time,
	}, true
}

// sbomStore reads SBOMSyft objects.
type sbomStore interface {
	// listSBOMs returns the metadata of every SBOMSyft.
	listSBOMs(ctx context.Context) ([]sbomMeta, error)
	// syftDocument returns the `.spec.syft` of one SBOMSyft as JSON.
	syftDocument(ctx context.Context, namespace, name string) ([]byte, error)
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
func (s storageSBOMs) syftDocument(ctx context.Context, namespace, name string) ([]byte, error) {
	raw, err := s.client.SpdxV1beta1().RESTClient().Get().
		Namespace(namespace).Resource("sbomsyfts").Name(name).
		SetHeader("Accept", "application/json").
		Do(ctx).Raw()
	if err != nil {
		return nil, fmt.Errorf("get SBOMSyft %s/%s: %w", namespace, name, err)
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
