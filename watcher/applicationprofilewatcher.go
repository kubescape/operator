package watcher

import (
	"context"
	"fmt"
	"slices"
	"time"

	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/containerinstance"
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

// ApplicationProfileWatch watches and processes changes on ApplicationProfile resources
func (wh *WatchHandler) ApplicationProfileWatch(ctx context.Context, workerPool *ants.PoolWithFunc) {
	inputEvents := make(chan watch.Event)
	cmdCh := make(chan *apis.Command)
	errorCh := make(chan error)
	apEvents := make(<-chan watch.Event)

	// The watcher is considered unavailable by default
	apWatcherUnavailable := make(chan struct{})
	go func() {
		apWatcherUnavailable <- struct{}{}
	}()

	go wh.HandleApplicationProfileEvents(inputEvents, cmdCh, errorCh)

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
		case apEvent, ok := <-apEvents:
			if ok {
				inputEvents <- apEvent
			} else {
				notifyWatcherDown(apWatcherUnavailable)
			}
		case cmd, ok := <-cmdCh:
			if ok {
				utils.AddCommandToChannel(ctx, wh.cfg, cmd, workerPool)
			} else {
				notifyWatcherDown(apWatcherUnavailable)
			}
		case err, ok := <-errorCh:
			if ok {
				logger.L().Ctx(ctx).Error(fmt.Sprintf("error in ApplicationProfileWatch: %v", err.Error()))
			} else {
				notifyWatcherDown(apWatcherUnavailable)
			}
		case <-apWatcherUnavailable:
			if watcher != nil {
				watcher.Stop()
			}

			watcher, err = wh.getApplicationProfileWatcher()
			if err != nil {
				notifyWatcherDown(apWatcherUnavailable)
			} else {
				apEvents = watcher.ResultChan()
			}
		}
	}

}

func (wh *WatchHandler) HandleApplicationProfileEvents(sfEvents <-chan watch.Event, producedCommands chan<- *apis.Command, errorCh chan<- error) {
	defer close(errorCh)

	for e := range sfEvents {
		obj, ok := e.Object.(*spdxv1beta1.ApplicationProfile)
		if !ok {
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

		if skipAP(obj.ObjectMeta.Annotations) {
			continue
		}

		// FIXME move this to kubevuln and only send the AP name and namespace
		fullAP, err := wh.getApplicationProfile(obj.Namespace, obj.Name)
		if err != nil {
			logger.L().Error("failed to get full application profile", helpers.String("name", obj.ObjectMeta.Name), helpers.String("namespace", obj.ObjectMeta.Namespace), helpers.Error(err))
			errorCh <- err
			continue
		}

		// loop through all containers in the application profile
		processContainers := func(containers []spdxv1beta1.ApplicationProfileContainer, containerType string) {
			for _, container := range containers {
				// create container data
				containerData, err := getContainerData(fullAP, container, containerType)
				if err != nil {
					logger.L().Error("failed to get container data from application profile",
						helpers.String("name", fullAP.ObjectMeta.Name),
						helpers.String("namespace", fullAP.ObjectMeta.Namespace),
						helpers.String("container", container.Name),
						helpers.Error(err))
					errorCh <- err
					continue
				}
				// update caches
				if imageID, ok := wh.SlugToImageID.Load(containerData.Slug); !ok {
					wh.SlugToImageID.Set(containerData.Slug, containerData.ImageID)
					wh.WlidAndImageID.Add(getWlidAndImageID(containerData))
				} else {
					if imageID != containerData.ImageID {
						wh.SlugToImageID.Set(containerData.Slug, containerData.ImageID)
						wh.WlidAndImageID.Add(getWlidAndImageID(containerData))
					}
				}
				// create command
				cmd := &apis.Command{
					Wlid:        containerData.Wlid,
					CommandName: utils.CommandScanApplicationProfile,
					Args: map[string]interface{}{
						utils.ArgsContainerData: containerData,
					},
				}
				// send command
				logger.L().Info("scanning application profile container", helpers.String("wlid", cmd.Wlid), helpers.String("slug", containerData.Slug), helpers.String("containerName", containerData.ContainerName), helpers.String("imageTag", containerData.ImageTag), helpers.String("imageID", containerData.ImageID))
				producedCommands <- cmd
			}
		}
		processContainers(fullAP.Spec.InitContainers, instanceidhandlerv1.InitContainer)
		processContainers(fullAP.Spec.Containers, instanceidhandlerv1.Container)
		processContainers(fullAP.Spec.EphemeralContainers, instanceidhandlerv1.EphemeralContainer)
	}
}

func getContainerData(obj *spdxv1beta1.ApplicationProfile, container spdxv1beta1.ApplicationProfileContainer, containerType string) (*utils.ContainerData, error) {
	// get instance ID string from annotations
	instanceIDString, ok := obj.Annotations[helpersv1.InstanceIDMetadataKey]
	if !ok {
		return nil, fmt.Errorf("missing instance ID in annotations")
	}
	// generate instance ID
	instanceID, err := instanceidhandlerv1.GenerateInstanceIDFromString(instanceIDString)
	if err != nil {
		return nil, fmt.Errorf("failed to generate instance ID: %w", err)
	}
	// add container name and type to instance ID
	instanceID.(*containerinstance.InstanceID).ContainerName = container.Name
	instanceID.(*containerinstance.InstanceID).InstanceType = containerType
	// generate slug
	slug, err := instanceID.GetSlug(false)
	if err != nil {
		return nil, fmt.Errorf("failed to generate slug: %w", err)
	}
	// create container data
	containerData := &utils.ContainerData{
		ImageTag:      container.ImageTag,
		ImageID:       container.ImageID,
		InstanceID:    instanceID.GetStringFormatted(),
		ContainerName: container.Name,
		ContainerType: containerType,
		Slug:          slug,
		Wlid:          obj.Annotations[helpersv1.WlidMetadataKey],
	}
	// validate container data
	if err := validateContainerDataApplicationProfiles(containerData); err != nil {
		return nil, fmt.Errorf("failed to validate container data: %w", err)
	}
	return containerData, nil
}

func skipAP(annotations map[string]string) bool {
	ann := []string{
		"", // empty string for backward compatibility
		helpersv1.Ready,
		helpersv1.Completed,
	}

	if len(annotations) == 0 {
		return true // skip
	}

	if status, ok := annotations[helpersv1.StatusMetadataKey]; ok {
		return !slices.Contains(ann, status)
	}
	return false // do not skip
}

func (wh *WatchHandler) getApplicationProfile(namespace, name string) (*spdxv1beta1.ApplicationProfile, error) {
	return wh.storageClient.SpdxV1beta1().ApplicationProfiles(namespace).Get(context.Background(), name, v1.GetOptions{})
}

func (wh *WatchHandler) getApplicationProfileWatcher() (watch.Interface, error) {
	// no need to support ExcludeNamespaces and IncludeNamespaces since node-agent will respect them as well
	return wh.storageClient.SpdxV1beta1().ApplicationProfiles("").Watch(context.Background(), v1.ListOptions{})
}

func validateContainerDataApplicationProfiles(containerData *utils.ContainerData) error {
	if containerData.ContainerName == "" {
		return ErrMissingContainerName
	}
	if containerData.ImageID == "" {
		return ErrMissingImageID
	}
	if containerData.Slug == "" {
		return ErrMissingSlug
	}
	if containerData.Wlid == "" {
		return ErrMissingWLID
	}
	if containerData.ImageTag == "" {
		return ErrMissingImageTag
	}
	if containerData.InstanceID == "" {
		return ErrMissingInstanceID
	}
	return nil
}
