package utils

import "slices"

// NativeDefaultFrameworks is the legacy posture framework set used for
// full-cluster scans (startup, exception rescan) when clusterData has no
// defaultFrameworks.
var NativeDefaultFrameworks = []string{"allcontrols", "nsa", "mitre"}

// FrameworksOrDefault returns a copy of frameworks, or of fallback when empty.
func FrameworksOrDefault(frameworks, fallback []string) []string {
	if len(frameworks) > 0 {
		return slices.Clone(frameworks)
	}
	return slices.Clone(fallback)
}
