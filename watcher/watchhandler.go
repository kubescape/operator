package watcher

import (
	"errors"
	"fmt"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const retryInterval = 1 * time.Second

var (
	ErrMissingWLID          = fmt.Errorf("missing WLID")
	ErrMissingWlid          = ErrMissingWLID // alias used by SBOM watcher retry path
	ErrMissingSlug          = fmt.Errorf("missing slug")
	ErrMissingImageTag      = fmt.Errorf("missing image tag")
	ErrMissingImageID       = fmt.Errorf("missing image ID")
	ErrMissingInstanceID    = fmt.Errorf("missing instanceID")
	ErrMissingContainerName = fmt.Errorf("missing container name")
	ErrUnsupportedObject    = errors.New("unsupported object type")
)

type WatchHandler struct {
	ImageToContainerData maps.SafeMap[string, utils.ContainerData] // map of <hash> : <container data>
	SlugToImageID        maps.SafeMap[string, string]              // map of <Slug> : string <image ID>
	WlidAndImageID       mapset.Set[string]                        // set of <wlid+imageID>
	sbomRetryAttempts    maps.SafeMap[string, int]                 // map of <SBOM key> : retry attempts so far
	storageClient        kssc.Interface
	cfg                  config.IConfig
	k8sAPI               *k8sinterface.KubernetesApi
	eventQueue           *CooldownQueue
	sbomObserver         SBOMObserver // also told about SBOMWatch's events, when set
	imageScansDisabled   bool         // SBOMWatch sends no scan commands (kubevuln is off)
}

// SBOMObserver is told about the pod and SBOM events SBOMWatch receives, such
// as the SBOM exporter.
type SBOMObserver interface {
	ObservePod(eventType watch.EventType, pod *corev1.Pod)
	ObserveSBOM(eventType watch.EventType, sbom *spdxv1beta1.SBOMSyft)
}

// SetSBOMObserver makes SBOMWatch pass its pod and SBOM events to o.
func (wh *WatchHandler) SetSBOMObserver(o SBOMObserver) {
	wh.sbomObserver = o
}

// DisableImageScans stops SBOMWatch from sending scan commands, for when it
// runs only for an SBOMObserver.
func (wh *WatchHandler) DisableImageScans() {
	wh.imageScansDisabled = true
}

// NewWatchHandler creates a new WatchHandler, initializes the maps and returns it
func NewWatchHandler(cfg config.IConfig, k8sAPI *k8sinterface.KubernetesApi, storageClient kssc.Interface, eventQueue *CooldownQueue) *WatchHandler {
	return &WatchHandler{
		storageClient:  storageClient,
		k8sAPI:         k8sAPI,
		cfg:            cfg,
		WlidAndImageID: mapset.NewSet[string](),
		eventQueue:     eventQueue,
	}
}
