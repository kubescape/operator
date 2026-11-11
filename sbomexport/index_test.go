package sbomexport

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// fakeClock is a time source a test moves by hand.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestIndex() (*index, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
	return newIndex(time.Hour, clock.now), clock
}

func TestIndexListsEveryNamespaceAnImageRunsIn(t *testing.T) {
	x, _ := newTestIndex()

	assert.Equal(t, []string{"sha256:a"}, x.setPod("apps/web", "apps", []string{"sha256:a"}))
	assert.Equal(t, []string{"sha256:a", "sha256:b"}, x.setPod("jobs/batch", "jobs", []string{"sha256:b", "sha256:a", "sha256:a"}))
	assert.Empty(t, x.setPod("apps/web-2", "apps", []string{"sha256:a"}), "already runs in apps")

	assert.Equal(t, []string{"apps", "jobs"}, x.namespaces("sha256:a"))
	assert.Equal(t, []string{"jobs"}, x.namespaces("sha256:b"))
	assert.Equal(t, []string{"sha256:a", "sha256:b"}, x.digests())
}

// A Modified event for a pod that keeps its images must not queue them again.
func TestIndexDoesNotReportAnUnchangedPodAsStarted(t *testing.T) {
	x, _ := newTestIndex()
	assert.Equal(t, []string{"sha256:a"}, x.setPod("apps/web", "apps", []string{"sha256:a"}))

	assert.Empty(t, x.setPod("apps/web", "apps", []string{"sha256:a"}))
	assert.Equal(t, []string{"sha256:b"}, x.setPod("apps/web", "apps", []string{"sha256:a", "sha256:b"}))
	assert.Equal(t, []string{"apps"}, x.namespaces("sha256:a"))
}

func TestIndexKeepsANamespaceForOneGracePeriodAfterItsLastPod(t *testing.T) {
	x, clock := newTestIndex()
	x.setPod("apps/web", "apps", []string{"sha256:a"})
	x.setPod("apps/web-2", "apps", []string{"sha256:a"})

	x.removePod("apps/web")
	clock.t = clock.t.Add(2 * time.Hour)
	assert.Equal(t, []string{"apps"}, x.namespaces("sha256:a"), "web-2 still runs")

	x.removePod("apps/web-2")
	clock.t = clock.t.Add(59 * time.Minute)
	assert.Equal(t, []string{"apps"}, x.namespaces("sha256:a"), "inside the grace period")
	assert.Equal(t, []string{"sha256:a"}, x.digests())

	clock.t = clock.t.Add(time.Minute)
	assert.Empty(t, x.namespaces("sha256:a"))
	assert.Empty(t, x.digests())
}

func TestIndexForgetsTheEndOfAnImageThatRunsAgain(t *testing.T) {
	x, clock := newTestIndex()
	x.setPod("apps/web", "apps", []string{"sha256:a"})
	x.removePod("apps/web")

	assert.Equal(t, []string{"sha256:a"}, x.setPod("apps/web", "apps", []string{"sha256:a"}), "runs again")
	clock.t = clock.t.Add(2 * time.Hour)
	assert.Equal(t, []string{"apps"}, x.namespaces("sha256:a"))
}

func TestIndexMovesAPodToItsNewImage(t *testing.T) {
	x, _ := newTestIndex()
	x.setPod("apps/web", "apps", []string{"sha256:old"})

	assert.Equal(t, []string{"sha256:new"}, x.setPod("apps/web", "apps", []string{"sha256:new"}))
	assert.Equal(t, []string{"apps"}, x.namespaces("sha256:old"), "the old image is in its grace period")
	assert.Equal(t, []string{"apps"}, x.namespaces("sha256:new"))
}

func TestIndexReplaceStartsTheGracePeriodOfWhatStopped(t *testing.T) {
	x, clock := newTestIndex()
	x.setPod("apps/web", "apps", []string{"sha256:a"})
	x.setPod("jobs/batch", "jobs", []string{"sha256:b"})

	x.replace(map[string]podEntry{
		"apps/web": {namespace: "apps", digests: []string{"sha256:a"}},
		"apps/api": {namespace: "apps", digests: []string{"sha256:c"}},
	}, nil)
	assert.Equal(t, []string{"sha256:a", "sha256:b", "sha256:c"}, x.digests())

	clock.t = clock.t.Add(time.Hour)
	assert.Equal(t, []string{"sha256:a", "sha256:c"}, x.digests(), "batch stopped an hour ago")
	assert.Equal(t, []string{"apps"}, x.namespaces("sha256:a"))
}
