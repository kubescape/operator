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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func SkipApplicationProfile(annotations map[string]string) (bool, error) {
	ann := []string{
		"", // empty string for backward compatibility
		helpersv1.Ready,
		helpersv1.Completed,
	}

	if len(annotations) == 0 {
		return true, fmt.Errorf("No Annotations") // skip
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

// GetApplicationProfileForRelevancyScan retrieves an application profile from the storage client based on the provided slug and namespace
// If the application profile is found, and it should not be skipped (i.e. correct status, InstanceID and WLID annotations), it is returned, otherwise nil
func GetApplicationProfileForRelevancyScan(ctx context.Context, storageClient kssc.Interface, slug, namespace string) *v1beta1.ApplicationProfile {
	appProfile, err := storageClient.SpdxV1beta1().ApplicationProfiles(namespace).Get(ctx, slug, metav1.GetOptions{ResourceVersion: "metadata"})
	if err == nil && appProfile != nil {
		if skip, err := SkipApplicationProfile(appProfile.Annotations); skip {
			logger.L().Info("found application profile, but skipping", helpers.Error(err), helpers.String("id", slug), helpers.String("namespace", namespace),
				helpers.Interface("annotations", appProfile.Annotations))
			return nil
		} else {
			logger.L().Info("found application profile", helpers.String("id", slug), helpers.String("namespace", namespace))
			return appProfile
		}
	} else {
		logger.L().Info("application profile not found", helpers.String("id", slug), helpers.String("namespace", namespace))
	}
	return nil
}

func GetApplicationProfileScanCommand(appProfile *v1beta1.ApplicationProfile) *apis.Command {
	return &apis.Command{
		Wlid:        appProfile.Annotations[helpersv1.WlidMetadataKey],
		CommandName: apis.TypeScanApplicationProfile,
		Args: map[string]interface{}{
			ArgsName:      appProfile.Name,
			ArgsNamespace: appProfile.Namespace,
		},
	}
}
