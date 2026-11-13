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

// A namespace whose root or parent is missing and may not be created is
// skipped, and nothing is created for it.
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

// With a mutable tag, each namespace has its own project for the same tag. A
// new build rolled out in one namespace takes over that namespace's project
// even while another namespace, with its own project, still runs the old
// build.
func TestExporterTakesOverAProjectWhoseOwnerOnlyRunsElsewhere(t *testing.T) {
	const (
		oldID = "docker.io/library/app@sha256:aaaa"
		newID = "docker.io/library/app@sha256:bbbb"
		tag   = "docker.io/library/app:main"
	)
	ctx := context.Background()
	te := newTestExporter(t, runningPod("staging", "web", oldID), runningPod("prod", "web", oldID))
	oldSBOM := sbomObject(oldID, tag, helpersv1.Learning, te.clock.t.Add(-time.Hour))
	te.store.set(oldSBOM)
	require.NoError(t, te.resync(ctx))
	require.Empty(t, te.drain())
	require.Len(t, te.dt.takeUploads(), 2)

	// staging rolls out a new build of the same tag; prod keeps the old one
	_, err := te.client.CoreV1().Pods("staging").Update(ctx, runningPod("staging", "web", newID), metav1.UpdateOptions{})
	require.NoError(t, err)
	te.store.set(oldSBOM, sbomObject(newID, tag, helpersv1.Learning, te.clock.t))
	require.NoError(t, te.resync(ctx))
	require.Empty(t, te.drain())
	te.clock.t = te.clock.t.Add(2 * time.Hour) // the old build's grace period in staging is over
	te.stats.takeFields()
	require.NoError(t, te.resync(ctx))
	require.Empty(t, te.drain())

	require.Equal(t, []string{"prod"}, te.running.namespaces("sha256:aaaa"))
	assert.Equal(t, []string{"cluster/staging/docker.io/library/app:main"}, te.dt.takeUploads())
	assert.Zero(t, te.stats.conflicts.Load())
	p, _, ok := te.dt.project("cluster/staging/docker.io/library/app", "main")
	require.True(t, ok)
	owner, err := te.dt.digestOwnerForTest(p.UUID)
	require.NoError(t, err)
	assert.Equal(t, "sha256:bbbb", owner)
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
	t.Run("by the object it reads, when the annotation is missing", func(t *testing.T) {
		te := newTestExporter(t, runningPod("apps", "web", redisImageID))
		te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
		te.store.tooLarge = true

		require.NoError(t, te.resync(context.Background()))
		require.Empty(t, te.drain())

		assert.Empty(t, te.dt.takeUploads())
		assert.Equal(t, int64(1), te.stats.tooLarge.Load())
		assert.Equal(t, int64(10<<20+objectOverhead), te.store.lastLimit())
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

// The namespace a pod event names is resolved when the image is exported, so
// an image seen before its Namespace object still lands in the right place.
func TestExporterUsesTheNamespaceAnnotationsWhenItExports(t *testing.T) {
	te := newTestExporter(t, namespace("payments", map[string]string{AnnotationProjectName: "{{ .Repository }}"}))
	te.ObserveSBOM(watch.Added, sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	te.ObservePod(watch.Added, runningPod("payments", "api", redisImageID))

	require.Empty(t, te.drain())

	assert.Equal(t, []string{redisProject + ":8"}, te.dt.takeUploads())
}

// The image's digest is recorded on its project before the upload, so a
// project never holds a BOM without an owner another image could take.
func TestExporterUploadsOnlyAfterRecordingTheImage(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID))
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	te.dt.failProperties = 1

	require.NoError(t, te.resync(context.Background()))
	assert.Len(t, te.drain(), 1)
	assert.Empty(t, te.dt.takeUploads(), "no upload without a recorded owner")

	te.queue.Add(digestOf(redisImageID))
	require.Empty(t, te.drain())
	assert.Equal(t, []string{"cluster/apps/" + redisProject + ":8"}, te.dt.takeUploads())
	p, _, _ := te.dt.project("cluster/apps/"+redisProject, "8")
	owner, err := te.dt.digestOwnerForTest(p.UUID)
	require.NoError(t, err)
	assert.Equal(t, digestOf(redisImageID), owner)
}

func TestCollectionKeepsReferencesThatOnlyDifferInWhereTheColonIs(t *testing.T) {
	te := newTestExporter(t)
	a := te.dt.addProject("team:ops", "current", "")
	b := te.dt.addProject("team", "ops:current", "")

	gotA, err := te.collection(context.Background(), projectRef{name: "team:ops", version: "current"}, false, parentLogic, nil)
	require.NoError(t, err)
	gotB, err := te.collection(context.Background(), projectRef{name: "team", version: "ops:current"}, false, parentLogic, nil)
	require.NoError(t, err)

	assert.Equal(t, a, gotA)
	assert.Equal(t, b, gotB)
}

func TestExporterMovesAProjectWhenOnlyItsParentChanges(t *testing.T) {
	annotations := map[string]string{AnnotationParent: "Team A:current", AnnotationProjectName: "{{ .Repository }}"}
	te := newTestExporter(t, namespace("payments", annotations), runningPod("payments", "api", redisImageID))
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	before, parent, _ := te.dt.project(redisProject, "8")
	require.Equal(t, "Team A", parent)
	te.dt.takeUploads()

	annotations[AnnotationParent] = "Team B:current"
	te.updateNamespace(t, namespace("payments", annotations))
	require.Empty(t, te.drain())

	after, parent, _ := te.dt.project(redisProject, "8")
	assert.Equal(t, before.UUID, after.UUID)
	assert.Equal(t, "Team B", parent)
	assert.Empty(t, te.dt.takeUploads())
}

// A parent the exporter created follows its namespace's root.
func TestExporterMovesItsParentWhenOnlyTheRootChanges(t *testing.T) {
	te := newTestExporter(t, namespace("payments", nil), runningPod("payments", "api", redisImageID))
	te.dt.addProject("Finance", "current", "")
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	parent, root, _ := te.dt.project("cluster/payments", "current")
	require.Equal(t, "cluster", root)
	patches := te.dt.patchCount(parent.UUID)

	te.updateNamespace(t, namespace("payments", map[string]string{AnnotationRootProject: "Finance:current", AnnotationRootProjectCreate: "false"}))
	require.Empty(t, te.drain())

	parent, root, _ = te.dt.project("cluster/payments", "current")
	assert.Equal(t, "Finance", root)
	assert.Equal(t, parentLogic, parent.CollectionLogic)
	assert.Equal(t, 1, te.dt.patchCount(parent.UUID)-patches, "one PATCH moves it and keeps its collection logic")
	finance, _, _ := te.dt.project("Finance", "current")
	assert.Empty(t, finance.Tags, "the root itself is not changed")
}

// A layout change that comes in while the previous one is being moved is not
// lost: the projects end up where the latest layout puts them.
func TestExporterKeepsALayoutChangeThatComesInDuringAMove(t *testing.T) {
	te := newTestExporter(t, namespace("payments", nil), runningPod("payments", "api", redisImageID))
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	before, _, _ := te.dt.project("cluster/payments/"+redisProject, "8")

	toC := namespace("payments", map[string]string{AnnotationParent: "Team C:current", AnnotationProjectName: "{{ .Repository }}"})
	te.dt.onPatch = func() {
		// while the move to B patches the project, the namespace changes to C
		seq := te.moveSeqForTest()
		_, err := te.client.CoreV1().Namespaces().Update(context.Background(), toC, metav1.UpdateOptions{})
		assert.NoError(t, err)
		assert.Eventually(t, func() bool { return te.moveSeqForTest() > seq }, 5*time.Second, 10*time.Millisecond)
	}
	te.updateNamespace(t, namespace("payments", map[string]string{AnnotationParent: "Team B:current", AnnotationProjectName: "{{ .Repository }}"}))
	require.Empty(t, te.drain())

	after, parent, ok := te.dt.project(redisProject, "8")
	require.True(t, ok)
	assert.Equal(t, before.UUID, after.UUID)
	assert.Equal(t, "Team C", parent)
}

// A move whose parent is missing and may not be created waits, and is done at
// a resync once the parent exists.
func TestExporterKeepsAMoveWhoseParentIsMissingUntilItExists(t *testing.T) {
	te := newTestExporter(t, namespace("payments", nil), runningPod("payments", "api", redisImageID))
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	before, _, _ := te.dt.project("cluster/payments/"+redisProject, "8")

	te.updateNamespace(t, namespace("payments", map[string]string{AnnotationParent: "Team B:current", AnnotationParentCreate: "false"}))
	require.Empty(t, te.drain())
	_, parent, _ := te.dt.project("cluster/payments/"+redisProject, "8")
	require.Equal(t, "cluster/payments", parent, "Team B does not exist yet")

	te.dt.addProject("Team B", "current", "")
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())

	after, parent, _ := te.dt.project("cluster/payments/"+redisProject, "8")
	assert.Equal(t, before.UUID, after.UUID)
	assert.Equal(t, "Team B", parent)
	assert.Equal(t, int64(1), te.stats.moved.Load())

	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	assert.Zero(t, te.stats.moved.Load(), "the move is done, not tried again")
}

// A root-only change moves the parent also when no image of the namespace
// can be exported, and waits while the new root is missing.
func TestExporterMovesTheParentWhenNoImageCanBeExported(t *testing.T) {
	te := newTestExporter(t, namespace("payments", nil), runningPod("payments", "api", redisImageID))
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	big := sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t)
	big.Annotations[helpersv1.ResourceSizeMetadataKey] = strconv.Itoa(11 << 20)
	te.store.set(big)
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())

	te.updateNamespace(t, namespace("payments", map[string]string{AnnotationRootProject: "Finance:current", AnnotationRootProjectCreate: "false"}))
	require.Empty(t, te.drain())
	_, root, _ := te.dt.project("cluster/payments", "current")
	require.Equal(t, "cluster", root, "Finance does not exist yet")

	te.dt.addProject("Finance", "current", "")
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())

	parent, root, _ := te.dt.project("cluster/payments", "current")
	assert.Equal(t, "Finance", root)
	assert.Equal(t, parentLogic, parent.CollectionLogic)
	assert.Empty(t, te.dt.takeUploads()[1:], "the SBOM is still too large")
}
