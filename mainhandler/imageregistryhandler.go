package mainhandler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	regCommon "github.com/armosec/registryx/common"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/pager"
)

type AuthMethods string

const (
	registryScanConfigmap                   = "kubescape-registry-scan"
	registryNameField                       = "registryName"
	secretNameField                         = "secretName"
	imagesToScanLimit                       = 500
	registriesAuthFieldInSecret             = "registriesAuth"
	accessTokenAuth             AuthMethods = "accesstoken"
	registryCronjobTemplate                 = "registry-scan-cronjob-template"
	tagsPageSize                            = 1000
	registryScanDocumentation               = "https://hub.armosec.io/docs/registry-vulnerability-scan"
)

type registryAuth struct {
	SkipTLSVerify *bool                  `json:"skipTLSVerify,omitempty"`
	Insecure      *bool                  `json:"http,omitempty"`
	Registry      string                 `json:"registry,omitempty"`
	AuthMethod    string                 `json:"auth_method,omitempty"`
	Username      string                 `json:"username,omitempty"`
	Password      string                 `json:"password,omitempty"`
	RegistryToken string                 `json:"registryToken,omitempty"`
	Kind          regCommon.RegistryKind `json:"kind,omitempty"`
}

func parseRegistryAuthSecret(secret k8sinterface.IWorkload) ([]registryAuth, error) {
	secretData := secret.GetData()
	var registriesAuth []registryAuth
	registriesAuthStr, ok := secretData[registriesAuthFieldInSecret].(string)
	if !ok {
		return nil, fmt.Errorf("error parsing Secret: %s field must be a string", registriesAuthFieldInSecret)
	}
	data, err := base64.StdEncoding.DecodeString(registriesAuthStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing Secret: %s", err.Error())
	}
	registriesAuthStr = strings.Replace(string(data), "\n", "", -1)

	if e := json.Unmarshal([]byte(registriesAuthStr), &registriesAuth); e != nil {
		return nil, fmt.Errorf("error parsing Secret: %s", e.Error())
	}

	return registriesAuth, nil
}

func getRegistryScanSecrets(k8sAPI *k8sinterface.KubernetesApi, namespace, secretName string) ([]k8sinterface.IWorkload, error) {
	if secretName != "" {
		secret, err := k8sAPI.GetWorkload(namespace, "Secret", secretName)
		if err == nil && secret != nil {
			return []k8sinterface.IWorkload{secret}, err
		}
	}

	// when secret name is not provided, we will try to find all secrets starting with kubescape-registry-scan
	var registryScanSecrets []k8sinterface.IWorkload
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return k8sAPI.KubernetesClient.CoreV1().Secrets(namespace).List(ctx, opts)
	}).EachListItem(k8sAPI.Context, metav1.ListOptions{}, func(obj runtime.Object) error {
		secret := obj.(*corev1.Secret)
		if strings.HasPrefix(secret.GetName(), registryScanConfigmap) {
			unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(secret)
			if err == nil {
				wl := workloadinterface.NewWorkloadObj(unstructuredObj)
				registryScanSecrets = append(registryScanSecrets, wl)
			}
		}
		return nil
	})
	return registryScanSecrets, err
}
