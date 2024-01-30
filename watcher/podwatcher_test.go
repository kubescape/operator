package watcher

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/containerinstance"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/initcontainerinstance"
	core1 "k8s.io/api/core/v1"
)

//go:embed testdata/pod-collection.json
var podJson []byte

//go:embed testdata/pod-with-some-empty-status.json
var podPartialStatus []byte

func bytesToPod(b []byte) *core1.Pod {
	var pod *core1.Pod
	json.Unmarshal(b, &pod)
	return pod
}

func podToInstanceIDs(p *core1.Pod) []instanceidhandler.IInstanceID {
	instanceIDs, _ := instanceidhandlerv1.GenerateInstanceIDFromPod(p)
	return instanceIDs
}

func Test_mapSlugToInstanceID(t *testing.T) {
	instanceIDs := podToInstanceIDs(bytesToPod(podJson))
	expected := map[string]instanceidhandler.IInstanceID{
		"replicaset-collection-69c659f8cb-alpine-container-9858-6638": instanceIDs[0],
		"replicaset-collection-69c659f8cb-redis-beb0-de8a":            instanceIDs[1],
		"replicaset-collection-69c659f8cb-wordpress-05df-a39f":        instanceIDs[2],
		"replicaset-collection-69c659f8cb-busybox-b1d9-e8c6":          instanceIDs[3],
		"replicaset-collection-69c659f8cb-alpine-3ac2-aecc":           instanceIDs[4],
	}

	result := mapSlugToInstanceID(instanceIDs)

	if len(result) != len(expected) {
		t.Errorf("Unexpected result length. Expected: %d, Got: %d", len(expected), len(result))
	}

	for slug, expectedInstanceID := range expected {
		resultInstanceID, ok := result[slug]
		if !ok {
			t.Errorf("Missing instance ID for slug: %s", slug)
			continue
		}

		if resultInstanceID != expectedInstanceID {
			t.Errorf("Unexpected instance ID for slug: %s. Expected: %v, Got: %v", slug, expectedInstanceID, resultInstanceID)
		}
	}
}
func Test_slugToImage(t *testing.T) {
	type args struct {
		slugToImageID   map[string]string
		instanceType    helpers.InstanceType
		instanceIDs     []instanceidhandler.IInstanceID
		containerStatus []core1.ContainerStatus
	}
	tests := []struct {
		expected map[string]string
		name     string
		args     args
	}{
		{
			name: "regular container",
			args: args{
				instanceIDs:     podToInstanceIDs(bytesToPod(podJson)),
				slugToImageID:   map[string]string{},
				containerStatus: bytesToPod(podJson).Status.ContainerStatuses,
				instanceType:    containerinstance.InstanceType,
			},
			expected: map[string]string{
				"replicaset-collection-69c659f8cb-alpine-container-9858-6638": "docker.io/library/alpine@sha256:82d1e9d7ed48a7523bdebc18cf6290bdb97b82302a8a9c27d4fe885949ea94d1",
				"replicaset-collection-69c659f8cb-redis-beb0-de8a":            "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
				"replicaset-collection-69c659f8cb-wordpress-05df-a39f":        "docker.io/library/wordpress@sha256:5f1873a461105cb1dc1a75731671125f1fb406b18e3fcf63210e8f7f84ce560b",
			},
		},
		{
			name: "init container",
			args: args{
				instanceIDs:     podToInstanceIDs(bytesToPod(podJson)),
				slugToImageID:   map[string]string{},
				containerStatus: bytesToPod(podJson).Status.InitContainerStatuses,
				instanceType:    initcontainerinstance.InstanceType,
			},
			expected: map[string]string{
				"replicaset-collection-69c659f8cb-busybox-b1d9-e8c6": "docker.io/library/busybox@sha256:e8e5cca392e3cf056fcdb3093e7ac2bf83fcf28b3bcf5818fe8ae71cf360c231",
				"replicaset-collection-69c659f8cb-alpine-3ac2-aecc":  "docker.io/library/alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
			},
		},
		{
			name: "missing container status",
			args: args{
				instanceIDs:     podToInstanceIDs(bytesToPod(podPartialStatus)),
				slugToImageID:   map[string]string{},
				containerStatus: bytesToPod(podPartialStatus).Status.ContainerStatuses,
				instanceType:    containerinstance.InstanceType,
			},
			expected: map[string]string{
				"replicaset-collection-69c659f8cb-alpine-container-9858-6638": "docker.io/library/alpine@sha256:82d1e9d7ed48a7523bdebc18cf6290bdb97b82302a8a9c27d4fe885949ea94d1",
				"replicaset-collection-69c659f8cb-redis-beb0-de8a":            "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
			},
		},
		{
			name: "wrong container type",
			args: args{
				instanceIDs:     podToInstanceIDs(bytesToPod(podPartialStatus)),
				slugToImageID:   map[string]string{},
				containerStatus: bytesToPod(podJson).Status.ContainerStatuses,
				instanceType:    "",
			},
			expected: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slugToImage(tt.args.instanceIDs, tt.args.slugToImageID, tt.args.containerStatus, tt.args.instanceType)

			if len(tt.args.slugToImageID) != len(tt.expected) {
				t.Errorf("Unexpected result length. Expected: %d, Got: %d", len(tt.expected), len(tt.args.slugToImageID))
			}

			for slug, expectedImageID := range tt.expected {
				resultImageID, ok := tt.args.slugToImageID[slug]
				if !ok {
					t.Errorf("Missing image ID for slug: %s", slug)
					continue
				}

				if resultImageID != expectedImageID {
					t.Errorf("Unexpected image ID for slug: %s. Expected: %v, Got: %v", slug, expectedImageID, resultImageID)
				}
			}
		})
	}
}

func Test_mapSlugsToImageIDs(t *testing.T) {
	type args struct {
		pod         *core1.Pod
		instanceIDs []instanceidhandler.IInstanceID
	}
	tests := []struct {
		expected map[string]string
		name     string
		args     args
	}{
		{
			name: "regular pod",
			args: args{
				instanceIDs: podToInstanceIDs(bytesToPod(podJson)),
				pod:         bytesToPod(podJson),
			},
			expected: map[string]string{
				"replicaset-collection-69c659f8cb-alpine-container-9858-6638": "docker.io/library/alpine@sha256:82d1e9d7ed48a7523bdebc18cf6290bdb97b82302a8a9c27d4fe885949ea94d1",
				"replicaset-collection-69c659f8cb-redis-beb0-de8a":            "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
				"replicaset-collection-69c659f8cb-wordpress-05df-a39f":        "docker.io/library/wordpress@sha256:5f1873a461105cb1dc1a75731671125f1fb406b18e3fcf63210e8f7f84ce560b",
				"replicaset-collection-69c659f8cb-busybox-b1d9-e8c6":          "docker.io/library/busybox@sha256:e8e5cca392e3cf056fcdb3093e7ac2bf83fcf28b3bcf5818fe8ae71cf360c231",
				"replicaset-collection-69c659f8cb-alpine-3ac2-aecc":           "docker.io/library/alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := mapSlugsToImageIDs(tt.args.pod, tt.args.instanceIDs)

			if len(l) != len(tt.expected) {
				t.Errorf("Unexpected result length. Expected: %d, Got: %d", len(tt.expected), len(l))
			}

			for slug, expectedImageID := range tt.expected {
				resultImageID, ok := l[slug]
				if !ok {
					t.Errorf("Missing image ID for slug: %s", slug)
					continue
				}

				if resultImageID != expectedImageID {
					t.Errorf("Unexpected image ID for slug: %s. Expected: %v, Got: %v", slug, expectedImageID, resultImageID)
				}
			}
		})
	}
}
