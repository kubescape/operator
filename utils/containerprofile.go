package utils

import (
	"context"
	"fmt"
	"slices"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func SkipContainerProfile(annotations map[string]string) (bool, error) {
	ann := []string{
		"", // empty string for backward compatibility
		helpersv1.Learning,
		helpersv1.Completed,
	}

	if len(annotations) == 0 {
		return true, fmt.Errorf("no annotations") // skip
	}

	if status, ok := annotations[helpersv1.StatusMetadataKey]; ok && !slices.Contains(ann, status) {
		return true, fmt.Errorf("invalid status")
	}
	if val, ok := annotations[helpersv1.InstanceIDMetadataKey]; !ok || val == "" {
		return true, fmt.Errorf("missing InstanceID annotation") // skip
	}
	if val, ok := annotations[helpersv1.WlidMetadataKey]; !ok || val == "" {
		return true, fmt.Errorf("missing WLID annotation") // skip
	}

	return false, nil // do not skip
}

// GetContainerProfileForRelevancyScan retrieves an container profile from the storage client based on the provided slug and namespace
// If the container profile is found, and it should not be skipped (i.e. correct status, InstanceID and WLID annotations), it is returned, otherwise nil
func GetContainerProfileForRelevancyScan(ctx context.Context, storageClient kssc.Interface, slug, namespace string) *v1beta1.ContainerProfile {
	profile, err := storageClient.SpdxV1beta1().ContainerProfiles(namespace).Get(ctx, slug, metav1.GetOptions{ResourceVersion: "metadata"})
	if err == nil && profile != nil {
		if skip, err := SkipContainerProfile(profile.Annotations); skip {
			logger.L().Info("found container profile, but skipping", helpers.Error(err), helpers.String("id", slug), helpers.String("namespace", namespace),
				helpers.Interface("annotations", profile.Annotations))
			return nil
		} else {
			logger.L().Info("found container profile", helpers.String("id", slug), helpers.String("namespace", namespace))
			return profile
		}
	} else {
		logger.L().Info("container profile not found", helpers.String("id", slug), helpers.String("namespace", namespace))
	}
	return nil
}

func GetContainerProfileScanCommand(profile *v1beta1.ContainerProfile, pod *corev1.Pod) *apis.Command {
	return &apis.Command{
		Wlid:        profile.Annotations[helpersv1.WlidMetadataKey],
		CommandName: apis.TypeScanApplicationProfile,
		Args: map[string]interface{}{
			ArgsName:      profile.Name,
			ArgsNamespace: profile.Namespace,
			ArgsPod:       pod,
		},
	}
}
