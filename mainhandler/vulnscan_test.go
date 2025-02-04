package mainhandler

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	dockerregistry "github.com/docker/docker/api/types/registry"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

func fileToPod(filePath string) *corev1.Pod {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	var pod *corev1.Pod
	err = json.Unmarshal(b, &pod)
	if err != nil {
		return nil
	}
	return pod
}

func fileToSecret(filePath string) *corev1.Secret {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	var secret *corev1.Secret
	err = json.Unmarshal(b, &secret)
	if err != nil {
		return nil
	}
	return secret
}

func Test_ActionHandler_getImageScanConfig(t *testing.T) {
	type args struct {
		namespace string
		pod       *corev1.Pod
		imageTag  string
	}
	tests := []struct {
		name    string
		args    args
		objects []runtime.Object
		want    *ImageScanConfig
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "no registry treated as docker.io",
			args: args{
				imageTag: "nginx:latest",
			},
			objects: []runtime.Object{fileToSecret("testdata/vulnscan/registry-secret.json")},
			want: &ImageScanConfig{
				insecure: ptr.To(true),
				authConfigs: []dockerregistry.AuthConfig{
					{Username: "test-user", Password: "test-pass", ServerAddress: "docker.io"},
					{Username: "test-user-quay", Password: "test-pass-quay", ServerAddress: "quay.io"},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "quay.IO",
			args: args{
				imageTag: "quay.IO/kubescape/nginx:latest",
			},
			objects: []runtime.Object{fileToSecret("testdata/vulnscan/registry-secret.json")},
			want: &ImageScanConfig{
				skipTLSVerify: ptr.To(true),
				authConfigs: []dockerregistry.AuthConfig{
					{Username: "test-user", Password: "test-pass", ServerAddress: "docker.io"},
					{Username: "test-user-quay", Password: "test-pass-quay", ServerAddress: "quay.io"},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "pod with registry secret",
			args: args{
				pod: fileToPod("testdata/vulnscan/pod.json"),
			},
			objects: []runtime.Object{fileToSecret("testdata/vulnscan/regcreds.json")},
			want: &ImageScanConfig{
				authConfigs: []dockerregistry.AuthConfig{
					{Username: "YWRtaW4=", Password: "SGFyYm9yMTIzNDU=", Auth: "YWRtaW46SGFyYm9yMTIzNDU=", ServerAddress: "private.docker.io"},
					{Username: "matthyx", Password: "toto", Auth: "bWF0dGh5eDp0b3Rv", ServerAddress: "https://index.docker.io/v1/"},
				},
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sApiMock := &k8sinterface.KubernetesApi{
				Context:          context.TODO(),
				KubernetesClient: k8sfake.NewClientset(tt.objects...),
			}
			got, err := getImageScanConfig(k8sApiMock, tt.args.namespace, tt.args.pod, tt.args.imageTag)
			if !tt.wantErr(t, err, fmt.Sprintf("getImageScanConfig(%v, %v, %v, %v)", k8sApiMock, tt.args.namespace, tt.args.pod, tt.args.imageTag)) {
				return
			}
			assert.Equalf(t, tt.want, got, "getImageScanConfig(%v, %v, %v, %v)", k8sApiMock, tt.args.namespace, tt.args.pod, tt.args.imageTag)
		})
	}
}
