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
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
)

const retryInterval = 1 * time.Second

var (
	ErrMissingWLID          = fmt.Errorf("missing WLID")
	ErrMissingSlug          = fmt.Errorf("missing slug")
	ErrMissingImageTag      = fmt.Errorf("missing image ID")
	ErrMissingImageID       = fmt.Errorf("missing image tag")
	ErrMissingInstanceID    = fmt.Errorf("missing instanceID")
	ErrMissingContainerName = fmt.Errorf("missing container name")
	ErrUnsupportedObject    = errors.New("unsupported object type")
)

type WatchHandler struct {
	ImageToContainerData maps.SafeMap[string, utils.ContainerData] // map of <hash> : <container data>
	SlugToImageID        maps.SafeMap[string, string]              // map of <Slug> : string <image ID>
	WlidAndImageID       mapset.Set[string]                        // set of <wlid+imageID>
	storageClient        kssc.Interface
	cfg                  config.IConfig
	k8sAPI               *k8sinterface.KubernetesApi
	eventQueue           *CooldownQueue
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
