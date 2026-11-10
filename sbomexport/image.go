package sbomexport

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// digestOf returns the digest of an image ID, such as "sha256:abc" for
// "docker.io/library/redis@sha256:abc". An ID without "@" is returned as is.
// Pod container statuses and the kubescape.io/image-id annotation of an
// SBOMSyft both go through it, so the two sides compare equal.
func digestOf(imageID string) string {
	if i := strings.LastIndex(imageID, "@"); i >= 0 {
		return imageID[i+1:]
	}
	return imageID
}

// splitRef splits an image reference into the repository and the version its
// Dependency-Track project gets: the tag; without a tag, the first 12
// characters of the digest; with neither, "latest".
//
//	docker.io/library/redis:8-alpine       → docker.io/library/redis, 8-alpine
//	docker.io/library/redis@sha256:0123…   → docker.io/library/redis, 0123456789ab
//	localhost:5000/app                     → localhost:5000/app, latest
func splitRef(ref string) (repository, version string) {
	base, digest, hasDigest := strings.Cut(ref, "@")
	if i := strings.LastIndex(base, ":"); i > strings.LastIndex(base, "/") {
		return base[:i], base[i+1:]
	}
	if hasDigest {
		hex := digest[strings.LastIndex(digest, ":")+1:]
		return base, hex[:min(12, len(hex))]
	}
	return base, "latest"
}

// runningDigests returns the image digests of the containers that run in pod:
// its containers, and its init containers that are running (sidecars).
func runningDigests(pod *corev1.Pod) []string {
	if pod.Status.Phase != corev1.PodRunning {
		return nil
	}
	var digests []string
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.ImageID != "" {
			digests = append(digests, digestOf(cs.ImageID))
		}
	}
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.ImageID != "" && cs.State.Running != nil {
			digests = append(digests, digestOf(cs.ImageID))
		}
	}
	return digests
}
