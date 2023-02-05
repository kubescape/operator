package watcher

import (
	"context"
	"reflect"
	"testing"

	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/stretchr/testify/assert"
	core1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildImageIDsMap(t *testing.T) {
	podList := core1.PodList{
		Items: []core1.Pod{
			{
				Status: core1.PodStatus{
					ContainerStatuses: []core1.ContainerStatus{
						{
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
					},
				},
			},
			{
				Status: core1.PodStatus{
					ContainerStatuses: []core1.ContainerStatus{
						{
							ImageID: "alpine@sha256:2",
							Name:    "container-no-docker-pullable",
						},
					},
				},
			},
			{
				Status: core1.PodStatus{
					ContainerStatuses: []core1.ContainerStatus{
						{
							ImageID: "docker-pullable://alpine@sha256:3",
							Name:    "container3",
						},
						{
							ImageID: "docker-pullable://alpine@sha256:4",
							Name:    "container4",
						},
					},
				},
			},
		},
	}

	wh := NewWatchHandler()
	wh.buildImageIDsMap(&podList)

	expectedImageIDsMap := map[string]bool{
		"alpine@sha256:1": true,
		"alpine@sha256:2": true,
		"alpine@sha256:3": true,
		"alpine@sha256:4": true,
	}

	assert.True(t, reflect.DeepEqual(wh.GetImageIDsMap(), expectedImageIDsMap))

}

func TestBuildwlidsMap(t *testing.T) {
	podList := core1.PodList{
		Items: []core1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "namespace1",
				},
				Status: core1.PodStatus{
					ContainerStatuses: []core1.ContainerStatus{
						{
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod2",
					Namespace: "namespace2",
				},
				Status: core1.PodStatus{
					ContainerStatuses: []core1.ContainerStatus{
						{
							ImageID: "alpine@sha256:2",
							Name:    "container2",
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod3",
					Namespace: "namespace3",
				},
				Status: core1.PodStatus{
					ContainerStatuses: []core1.ContainerStatus{
						{
							ImageID: "docker-pullable://alpine@sha256:3",
							Name:    "container3",
						},
						{
							ImageID: "docker-pullable://alpine@sha256:4",
							Name:    "container4",
						},
					},
				},
			},
		},
	}

	wh := NewWatchHandler()
	wh.buildwlidsMap(context.TODO(), &podList)

	expectedwlidsMap := map[string]map[string]string{
		pkgwlid.GetWLID("", podList.Items[0].GetNamespace(), "pod", podList.Items[0].GetName()): {
			"container1": "alpine@sha256:1",
		},
		pkgwlid.GetWLID("", podList.Items[1].GetNamespace(), "pod", podList.Items[1].GetName()): {
			"container2": "alpine@sha256:2",
		},
		pkgwlid.GetWLID("", podList.Items[2].GetNamespace(), "pod", podList.Items[2].GetName()): {
			"container3": "alpine@sha256:3",
			"container4": "alpine@sha256:4",
		},
	}

	assert.True(t, reflect.DeepEqual(wh.GetWlidsMap(), expectedwlidsMap))

}

func TestAddToImageIDsMap(t *testing.T) {
	wh := NewWatchHandler()
	wh.imagesIDsMap = map[string]bool{
		"alpine@sha256:1": true,
	}
	wh.addToImageIDsMap("alpine@sha256:2")

	assert.True(t, reflect.DeepEqual(wh.GetImageIDsMap(), map[string]bool{
		"alpine@sha256:1": true,
		"alpine@sha256:2": true,
	}))
}

func TestAddTowlidsMap(t *testing.T) {
	wh := NewWatchHandler()
	wh.wlidsMap = map[string]map[string]string{
		"wlid": {
			"container1": "alpine@sha256:1",
		},
	}
	wh.addToWlidsMap("wlid2", "container2", "alpine@sha256:1")

	assert.True(t, reflect.DeepEqual(wh.GetWlidsMap(), map[string]map[string]string{
		"wlid": {
			"container1": "alpine@sha256:1",
		},
		"wlid2": {
			"container2": "alpine@sha256:1",
		},
	}))

}

func TestGetNewImages(t *testing.T) {
	wh := NewWatchHandler()
	wh.imagesIDsMap = map[string]bool{
		"alpine@sha256:1": true,
		"alpine@sha256:2": true,
		"alpine@sha256:3": true,
	}

	tests := []struct {
		name     string
		imageIDs []string
		expected []string
	}{
		{
			name:     "no new images",
			imageIDs: []string{"alpine@sha256:1", "alpine@sha256:2"},
			expected: []string{},
		},
		{
			name:     "one new image",
			imageIDs: []string{"alpine@sha256:1", "alpine@sha256:2", "alpine@sha256:4"},
			expected: []string{"alpine@sha256:4"},
		},
		{
			name:     "new images",
			imageIDs: []string{"alpine@sha256:7", "alpine@sha256:8", "alpine@sha256:9"},
			expected: []string{"alpine@sha256:7", "alpine@sha256:8", "alpine@sha256:9"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			containerStasues := []core1.ContainerStatus{}
			for _, imgID := range test.imageIDs {
				containerStasues = append(containerStasues, core1.ContainerStatus{
					ImageID: imgID,
				})
			}
			newImages := wh.getNewImages(&core1.Pod{
				Status: core1.PodStatus{
					ContainerStatuses: containerStasues,
				},
			})

			assert.True(t, reflect.DeepEqual(newImages, test.expected))
		})
	}
}
