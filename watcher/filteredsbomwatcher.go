package watcher

import (
	"context"
	"fmt"
	"slices"
	"time"

	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const retryInterval = 5 * time.Second

// SBOMFilteredWatch watches and processes changes on Filtered SBOMs
func (wh *WatchHandler) SBOMFilteredWatch(ctx context.Context, workerPool *ants.PoolWithFunc) {
	inputEvents := make(chan watch.Event)
	cmdCh := make(chan *apis.Command)
	errorCh := make(chan error)
	sbomEvents := make(<-chan watch.Event)

	// The watcher is considered unavailable by default
	sbomWatcherUnavailable := make(chan struct{})
	go func() {
		sbomWatcherUnavailable <- struct{}{}
	}()

	go wh.HandleSBOMFilteredEvents(inputEvents, cmdCh, errorCh)

	// notifyWatcherDown notifies the appropriate channel that the watcher
	// is down and backs off for the retry interval to not produce
	// unnecessary events
	notifyWatcherDown := func(watcherDownCh chan<- struct{}) {
		go func() { watcherDownCh <- struct{}{} }()
		time.Sleep(retryInterval)
	}

	var watcher watch.Interface
	var err error
	for {
		select {
		case sbomEvent, ok := <-sbomEvents:
			if ok {
				inputEvents <- sbomEvent
			} else {
				notifyWatcherDown(sbomWatcherUnavailable)
			}
		case cmd, ok := <-cmdCh:
			if ok {
				utils.AddCommandToChannel(ctx, wh.cfg, cmd, workerPool)
			} else {
				notifyWatcherDown(sbomWatcherUnavailable)
			}
		case err, ok := <-errorCh:
			if ok {
				logger.L().Ctx(ctx).Error(fmt.Sprintf("error in SBOMFilteredWatch: %v", err.Error()))
			} else {
				notifyWatcherDown(sbomWatcherUnavailable)
			}
		case <-sbomWatcherUnavailable:
			if watcher != nil {
				watcher.Stop()
			}

			watcher, err = wh.getSBOMFilteredWatcher()
			if err != nil {
				notifyWatcherDown(sbomWatcherUnavailable)
			} else {
				sbomEvents = watcher.ResultChan()
			}
		}
	}
}

func (wh *WatchHandler) HandleSBOMFilteredEvents(sfEvents <-chan watch.Event, producedCommands chan<- *apis.Command, errorCh chan<- error) {
	defer close(errorCh)

	for e := range sfEvents {
		obj, ok := e.Object.(*spdxv1beta1.SBOMSyftFiltered)
		if !ok {
			logger.L().Ctx(context.TODO()).Error("Unsupported object", helpers.String("expected", "spdxv1beta1.SBOMSyftFiltered"), helpers.Interface("got", e.Object))
			errorCh <- ErrUnsupportedObject
			continue
		}

		switch e.Type {
		case watch.Added:
		//
		case watch.Modified:
		//
		case watch.Deleted:
			continue
		case watch.Bookmark:
			continue
		}

		if skipSBOM(obj.ObjectMeta.Annotations) {
			continue
		}

		containerData, err := wh.getContainerDataFilteredSBOM(obj)
		if err != nil {
			logger.L().Ctx(context.TODO()).Error("failed to get container data from filtered SBOM",
				helpers.String("name", obj.ObjectMeta.Name),
				helpers.String("namespace", obj.ObjectMeta.Namespace),
				helpers.Interface("annotations", obj.ObjectMeta.Annotations),
				helpers.Error(err))
			continue
		}

		if imageID, ok := wh.SlugToImageID.Load(containerData.Slug); !ok {
			wh.SlugToImageID.Set(containerData.Slug, containerData.ImageID)
			wh.WlidAndImageID.Add(containerData.Wlid + containerData.ImageID)
		} else {
			if imageID != containerData.ImageID {
				wh.SlugToImageID.Set(containerData.Slug, containerData.ImageID)
				wh.WlidAndImageID.Add(containerData.Wlid + containerData.ImageID)
			}
		}

		cmd := &apis.Command{
			Wlid:        containerData.Wlid,
			CommandName: utils.CommandScanFilteredSBOM,
			Args: map[string]interface{}{
				utils.ArgsContainerData: containerData,
			},
		}
		producedCommands <- cmd
	}
}

func (wh *WatchHandler) getContainerDataFilteredSBOM(obj *spdxv1beta1.SBOMSyftFiltered) (*utils.ContainerData, error) {

	containerData, err := annotationsToContainerData(obj.GetAnnotations())
	if err != nil {
		return nil, err
	}

	// use cached image ID and tag. this is needed for backward compatibility
	// FIXME: use the annotations after adding imageID and imageTag to the filtered SBOM
	// containerData.ImageTag = wh.SlugToImageTag.Get(containerData.Slug)
	// containerData.ImageID = wh.SlugToImageID.Get(containerData.Slug)

	if err := validateContainerDataFilteredSBOM(containerData); err != nil {
		// missing data, fallback
		return nil, err
	}
	return containerData, nil
}

func annotationsToContainerData(annotations map[string]string) (*utils.ContainerData, error) {
	containerData := &utils.ContainerData{}
	rawInstanceID, ok := annotations[helpersv1.InstanceIDMetadataKey]
	if !ok {
		return containerData, fmt.Errorf("missing instance ID annotation")
	}

	instanceID, err := instanceidhandlerv1.GenerateInstanceIDFromString(rawInstanceID)
	if err != nil {
		return containerData, err
	}

	slug, err := instanceID.GetSlug()
	if err != nil {
		return containerData, err
	}
	containerData.Slug = slug
	containerData.Wlid = annotations[helpersv1.WlidMetadataKey]
	containerData.ContainerName = instanceID.GetContainerName()
	containerData.ContainerType = string(instanceID.GetInstanceType())

	// FIXME: use the annotations after adding imageID and imageTag to the filtered SBOM
	containerData.ImageID = annotations[helpersv1.ImageIDMetadataKey]
	containerData.ImageTag = annotations[helpersv1.ImageTagMetadataKey]

	return containerData, nil
}

func skipSBOM(annotations map[string]string) bool {
	ann := []string{
		"", // empty string for backward compatibility
		helpersv1.Ready,
		helpersv1.Completed,
	}
	if status, ok := annotations[helpersv1.StatusMetadataKey]; ok {
		return !slices.Contains(ann, status)
	}
	return false // do not skip
}

func (wh *WatchHandler) getSBOMFilteredWatcher() (watch.Interface, error) {
	return wh.storageClient.SpdxV1beta1().SBOMSyftFiltereds("").Watch(context.TODO(), v1.ListOptions{})
}

func validateContainerDataFilteredSBOM(containerData *utils.ContainerData) error {
	if containerData.ContainerName == "" {
		return fmt.Errorf("missing container name")
	}
	if containerData.ImageID == "" {
		return fmt.Errorf("missing image ID")
	}
	if containerData.Slug == "" {
		return fmt.Errorf("missing slug")
	}
	if containerData.Wlid == "" {
		return fmt.Errorf("missing WLID")
	}
	if containerData.ImageTag == "" {
		return fmt.Errorf("missing image tag")
	}
	return nil
}
