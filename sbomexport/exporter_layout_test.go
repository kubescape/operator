package sbomexport

import (
	"context"
	"strconv"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const nginxImageID = "docker.io/library/nginx@sha256:2222"

func TestExporterSendsANamespaceUnderAnExistingParentAndLeavesItAlone(t *testing.T) {
	te := newTestExporter(t,
		namespace("payments", map[string]string{
			AnnotationParent:       "Payments Team:current",
			AnnotationParentCreate: "false",
			AnnotationProjectName:  "{{ .Repository }}",
		}),
		runningPod("payments", "api", redisImageID),
	)
	finance := te.dt.addProject("Finance", "current", "")
	te.dt.addProject("Payments Team", "current", finance)
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))

	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())

	assert.Equal(t, []string{redisProject + ":8"}, te.dt.takeUploads())
	image, parent, _ := te.dt.project(redisProject, "8")
	assert.Equal(t, "Payments Team", parent)
	assert.True(t, image.managed())
	team, _, _ := te.dt.project("Payments Team", "current")
	assert.Empty(t, team.CollectionLogic, "an existing parent keeps its settings")
	assert.Empty(t, team.Tags)
	_, _, rootCreated := te.dt.project("cluster", "current")
	assert.False(t, rootCreated, "the root is only needed to create a parent")
}

func TestExporterCreatesTheParentUnderAnExistingRoot(t *testing.T) {
	te := newTestExporter(t,
		namespace("payments", map[string]string{
			AnnotationRootProject:       "Finance:current",
			AnnotationRootProjectCreate: "false",
			AnnotationParent:            "Payments Team:current",
		}),
		runningPod("payments", "api", redisImageID),
	)
	te.dt.addProject("Finance", "current", "")
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))

	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())

	team, parent, ok := te.dt.project("Payments Team", "current")
	require.True(t, ok)
	assert.Equal(t, "Finance", parent)
	assert.Equal(t, parentLogic, team.CollectionLogic)
	assert.True(t, team.managed())
	finance, _, _ := te.dt.project("Finance", "current")
	assert.Empty(t, finance.CollectionLogic, "an existing root keeps its settings")
	_, imageParent, _ := te.dt.project("cluster/payments/"+redisProject, "8")
	assert.Equal(t, "Payments Team", imageParent)
}

func TestExporterSkipsANamespaceWhoseProjectIsMissingAndMayNotBeCreated(t *testing.T) {
	tt := []struct {
		name        string
		annotations map[string]string
	}{
		{"parent with create false", map[string]string{AnnotationParent: "Payments Team:current", AnnotationParentCreate: "false"}},
		{"parent by an unknown UUID", map[string]string{AnnotationParent: "0a1b2c3d-0000-4000-8000-000000000099"}},
		{"root with create false", map[string]string{AnnotationRootProject: "Finance:current", AnnotationRootProjectCreate: "false"}},
		{"a layout that does not resolve", map[string]string{AnnotationProjectName: "{{ .Digest }}"}},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestExporter(t, namespace("payments", tc.annotations), runningPod("payments", "api", redisImageID))
			te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))

			require.NoError(t, te.resync(context.Background()))
			require.Empty(t, te.drain())

			assert.Empty(t, te.dt.takeUploads())
			assert.Zero(t, te.dt.count(), "nothing is created")
			assert.Equal(t, int64(1), te.stats.skippedLayout.Load())
		})
	}
}

func TestExporterNeverUploadsToAProjectItDidNotCreate(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID))
	te.dt.addProject("cluster/apps/"+redisProject, "8", "")
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))

	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())

	assert.Empty(t, te.dt.takeUploads())
	assert.Equal(t, int64(1), te.stats.conflicts.Load())
}

// Two images whose layout gives the same project and version would overwrite
// each other's BOM. The second is skipped while the first runs, and takes the
// project over once the first stopped.
func TestExporterKeepsTwoRunningImagesFromSharingOneProject(t *testing.T) {
	shared := map[string]string{AnnotationProjectName: "{{ .Namespace }}"}
	te := newTestExporter(t, namespace("apps", shared), runningPod("apps", "cache", redisImageID), runningPod("apps", "web", nginxImageID))
	te.store.set(
		sbomObject(redisImageID, "docker.io/library/redis:1.0", helpersv1.Learning, te.clock.t.Add(-time.Hour)),
		sbomObject(nginxImageID, "docker.io/library/nginx:1.0", helpersv1.Learning, te.clock.t.Add(-time.Hour)),
	)

	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	assert.Equal(t, []string{"apps:1.0"}, te.dt.takeUploads())
	assert.Equal(t, int64(1), te.stats.conflicts.Load())

	p, _, _ := te.dt.project("apps", "1.0")
	owner, err := te.dt.digestOwnerForTest(p.UUID)
	require.NoError(t, err)
	stopped, other := "cache", digestOf(nginxImageID)
	if owner == digestOf(nginxImageID) {
		stopped, other = "web", digestOf(redisImageID)
	}
	require.NoError(t, te.client.CoreV1().Pods("apps").Delete(context.Background(), stopped, metav1.DeleteOptions{}))
	require.NoError(t, te.resync(context.Background()))
	te.clock.t = te.clock.t.Add(2 * time.Hour)
	te.stats.takeFields()

	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	assert.Equal(t, []string{"apps:1.0"}, te.dt.takeUploads(), "the image that still runs takes the project over")
	owner, err = te.dt.digestOwnerForTest(p.UUID)
	require.NoError(t, err)
	assert.Equal(t, other, owner)
}

func TestExporterSkipsAnSBOMLargerThanTheLimit(t *testing.T) {
	t.Run("by its size annotation, without reading it", func(t *testing.T) {
		te := newTestExporter(t, runningPod("apps", "web", redisImageID))
		big := sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour))
		big.Annotations[helpersv1.ResourceSizeMetadataKey] = strconv.Itoa(11 << 20)
		te.store.set(big)

		require.NoError(t, te.resync(context.Background()))
		require.Empty(t, te.drain())

		assert.Empty(t, te.dt.takeUploads())
		assert.Zero(t, te.store.documentReads())
		assert.Equal(t, int64(1), te.stats.tooLarge.Load())
	})
	t.Run("by its document, when the annotation is missing", func(t *testing.T) {
		te := newTestExporterWith(t, func(o *Options) { o.MaxSBOMSize = 1000 }, runningPod("apps", "web", redisImageID))
		te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))

		require.NoError(t, te.resync(context.Background()))
		require.Empty(t, te.drain())

		assert.Empty(t, te.dt.takeUploads())
		assert.Equal(t, int64(1), te.stats.tooLarge.Load())
	})
}

func TestExporterMovesItsProjectsWhenANamespaceLayoutChanges(t *testing.T) {
	te := newTestExporter(t, namespace("payments", nil), runningPod("payments", "api", redisImageID))
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	before, _, ok := te.dt.project("cluster/payments/"+redisProject, "8")
	require.True(t, ok)
	te.dt.takeUploads()

	ns := namespace("payments", map[string]string{AnnotationParent: "Payments Team:current", AnnotationProjectName: "{{ .Repository }}"})
	_, err := te.client.CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return te.queue.Len() > 0 }, 5*time.Second, 10*time.Millisecond)
	require.Empty(t, te.drain())

	after, parent, ok := te.dt.project(redisProject, "8")
	require.True(t, ok)
	assert.Equal(t, before.UUID, after.UUID, "the same project moved, with its history")
	assert.Equal(t, "Payments Team", parent)
	_, _, stillThere := te.dt.project("cluster/payments/"+redisProject, "8")
	assert.False(t, stillThere)
	assert.Empty(t, te.dt.takeUploads(), "nothing is uploaded again")
	assert.Equal(t, int64(1), te.stats.moved.Load())
}

func TestExporterTagsItsProjectWhenDependencyTrackIgnoresProjectTags(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID))
	te.dt.ignoreUpTags = true
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))

	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())

	image, _, _ := te.dt.project("cluster/apps/"+redisProject, "8")
	assert.True(t, image.managed())
	te.clock.t = te.clock.t.Add(time.Hour)
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	assert.Equal(t, []string{"cluster/apps/" + redisProject + ":8"}, te.dt.takeUploads(), "the second resync finds it its own and unchanged")
}

// The namespace a pod event names is resolved when the image is exported, so
// an image seen before its Namespace object still lands in the right place.
func TestExporterUsesTheNamespaceAnnotationsWhenItExports(t *testing.T) {
	te := newTestExporter(t, namespace("payments", map[string]string{AnnotationProjectName: "{{ .Repository }}"}))
	te.ObserveSBOM(watch.Added, sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	te.ObservePod(watch.Added, runningPod("payments", "api", redisImageID))

	require.Empty(t, te.drain())

	assert.Equal(t, []string{redisProject + ":8"}, te.dt.takeUploads())
}
