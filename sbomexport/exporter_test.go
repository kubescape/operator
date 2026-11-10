package sbomexport

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

const (
	redisImageID = "docker.io/library/redis@sha256:1111"
	redisTag     = "docker.io/library/redis:8"
	redisProject = "docker.io/library/redis"
)

// fakeStore serves SBOMSyft objects from memory; every document is the curl
// fixture.
type fakeStore struct {
	mu    sync.Mutex
	sboms []*spdxv1beta1.SBOMSyft
	gets  int
}

func (s *fakeStore) listSBOMs(context.Context) ([]sbomMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []sbomMeta
	for _, obj := range s.sboms {
		if m, ok := metaOf(obj); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

func (s *fakeStore) syftDocument(context.Context, string, string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	return curlSyftJSON, nil
}

func (s *fakeStore) set(sboms ...*spdxv1beta1.SBOMSyft) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sboms = sboms
}

func (s *fakeStore) documentReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gets
}

type testExporter struct {
	*Exporter
	dt     *fakeDT
	store  *fakeStore
	clock  *fakeClock
	client *k8sfake.Clientset
}

// newTestExporter returns an Exporter with root project "cluster", a one-hour
// resync and kube-system excluded, over a fake Dependency-Track, a fake SBOM
// store and a fake clientset holding pods.
func newTestExporter(t *testing.T, pods ...runtime.Object) *testExporter {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
	dt, srv, keyFile := newFakeDT(t, clock.now)
	store := &fakeStore{}
	client := k8sfake.NewClientset(pods...)
	e, err := newExporter(Options{
		URL:            srv.URL,
		APIKeyFile:     keyFile,
		RootProject:    "cluster",
		ResyncInterval: time.Hour,
		SkipNamespace:  func(ns string) bool { return ns == "kube-system" },
	}, client, store, srv.Client(), clock.now)
	require.NoError(t, err)
	t.Cleanup(e.queue.ShutDown)
	return &testExporter{Exporter: e, dt: dt, store: store, clock: clock, client: client}
}

// drain processes every queued image once, as Start's worker would, and
// returns the errors.
func (te *testExporter) drain() []error {
	var errs []error
	for te.queue.Len() > 0 {
		digest, _ := te.queue.Get()
		if err := te.process(context.Background(), digest); err != nil {
			errs = append(errs, err)
		}
		te.queue.Forget(digest)
		te.queue.Done(digest)
	}
	return errs
}

func runningPod(namespace, name, imageID string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{Name: "main", ImageID: imageID}},
		},
	}
}

func sbomObject(imageID, imageTag, status string, created time.Time) *spdxv1beta1.SBOMSyft {
	return &spdxv1beta1.SBOMSyft{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "kubescape",
			Name:              "sbom-" + digestOf(imageID),
			CreationTimestamp: metav1.NewTime(created),
			Annotations: map[string]string{
				helpersv1.ImageIDMetadataKey:  imageID,
				helpersv1.ImageTagMetadataKey: imageTag,
				helpersv1.StatusMetadataKey:   status,
			},
		},
	}
}

func TestNewRejectsAnInvalidConfiguration(t *testing.T) {
	valid := Options{URL: "https://dtrack.example.com", APIKeyFile: "/etc/sbom-export/api-key", RootProject: "cluster", ResyncInterval: time.Hour}
	tt := []struct {
		name   string
		change func(*Options)
	}{
		{"no URL", func(o *Options) { o.URL = "" }},
		{"a URL without a scheme", func(o *Options) { o.URL = "dtrack.example.com" }},
		{"no API key file", func(o *Options) { o.APIKeyFile = "" }},
		{"no root project", func(o *Options) { o.RootProject = "" }},
		{"no resync interval", func(o *Options) { o.ResyncInterval = 0 }},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			opts := valid
			tc.change(&opts)
			_, err := New(opts, k8sfake.NewClientset(), nil)
			assert.Error(t, err)
		})
	}
	_, err := New(valid, k8sfake.NewClientset(), nil)
	assert.NoError(t, err)
}

func TestExporterSendsAnImageToTheProjectOfEveryNamespaceItRunsIn(t *testing.T) {
	te := newTestExporter(t,
		runningPod("apps", "web", redisImageID),
		runningPod("jobs", "worker", redisImageID),
		runningPod("kube-system", "cache", redisImageID),
	)
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))

	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())

	assert.ElementsMatch(t, []string{
		"cluster/apps/" + redisProject + ":8",
		"cluster/jobs/" + redisProject + ":8",
	}, te.dt.takeUploads(), "nothing for the excluded kube-system")
	assert.Equal(t, 1, te.store.documentReads(), "converted once for both namespaces")

	image, parent, _ := te.dt.project("cluster/apps/"+redisProject, "8")
	assert.Equal(t, "cluster/apps", parent)
	assert.True(t, image.IsLatest)
	namespace, parent, _ := te.dt.project("cluster/apps", collectionVersion)
	assert.Equal(t, "cluster", parent)
	assert.Equal(t, namespaceLogic, namespace.CollectionLogic)
	root, parent, _ := te.dt.project("cluster", collectionVersion)
	assert.Empty(t, parent)
	assert.Equal(t, clusterLogic, root.CollectionLogic)
}

func TestExporterSendsAnSBOMAgainOnlyWhenItIsNewerThanTheLastImport(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID))
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	te.dt.takeUploads()

	te.clock.t = te.clock.t.Add(time.Hour)
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	assert.Empty(t, te.dt.takeUploads(), "unchanged")

	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Minute)))
	te.clock.t = te.clock.t.Add(time.Hour)
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	assert.Equal(t, []string{"cluster/apps/" + redisProject + ":8"}, te.dt.takeUploads(), "the SBOMSyft is newer than the last import")
}

func TestExporterMarksTheRunningTagAsLatestWithoutSendingIt(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID))
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	te.dt.takeUploads()

	// another version of the image became the latest one
	p, _, _ := te.dt.project("cluster/apps/"+redisProject, "8")
	require.NoError(t, te.dt.patchForTest(p.UUID, false))

	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	assert.Empty(t, te.dt.takeUploads())
	p, _, _ = te.dt.project("cluster/apps/"+redisProject, "8")
	assert.True(t, p.IsLatest)
}

func TestExporterWaitsForTheSBOMToBeReady(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID))
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Initializing, te.clock.t.Add(-time.Hour)))
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	assert.Empty(t, te.dt.takeUploads())

	te.ObserveSBOM(watch.Modified, sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	require.Empty(t, te.drain())
	assert.Equal(t, []string{"cluster/apps/" + redisProject + ":8"}, te.dt.takeUploads())
}

func TestExporterSendsTheImageOfAJobThatEndedBeforeItsSBOMWasReady(t *testing.T) {
	te := newTestExporter(t)
	job := runningPod("jobs", "migrate-28937", redisImageID)

	te.ObservePod(watch.Added, job)
	te.ObservePod(watch.Deleted, job)
	te.clock.t = te.clock.t.Add(10 * time.Minute)
	te.ObserveSBOM(watch.Added, sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t))
	require.Empty(t, te.drain())
	assert.Equal(t, []string{"cluster/jobs/" + redisProject + ":8"}, te.dt.takeUploads())

	te.clock.t = te.clock.t.Add(time.Hour)
	require.NoError(t, te.resync(context.Background()))
	assert.Zero(t, te.queue.Len(), "the grace period is over")
}

func TestExporterRetriesWhatDependencyTrackRefused(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID))
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	require.NoError(t, te.resync(context.Background()))
	te.dt.failNext(1)

	assert.Len(t, te.drain(), 1)
	assert.Empty(t, te.dt.takeUploads())

	te.queue.Add(digestOf(redisImageID))
	require.Empty(t, te.drain())
	assert.Equal(t, []string{"cluster/apps/" + redisProject + ":8"}, te.dt.takeUploads())
}

func TestExporterResyncKeepsWhatItKnewWhenThePodListFails(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID))
	require.NoError(t, te.resync(context.Background()))
	listErr := errors.New("pods are unavailable")
	te.client.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, listErr
	})

	assert.ErrorIs(t, te.resync(context.Background()), listErr)
	assert.Equal(t, []string{"apps"}, te.running.namespaces(digestOf(redisImageID)))
}

func TestStartExportsUntilTheContextEnds(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID))
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		te.Start(ctx)
	}()

	var uploads []string
	assert.Eventually(t, func() bool {
		uploads = append(uploads, te.dt.takeUploads()...)
		return slices.Contains(uploads, "cluster/apps/"+redisProject+":8")
	}, 10*time.Second, 50*time.Millisecond)

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after the context ended")
	}
}

func TestExporterCountsARefusedAPIKeyAsAFailureAndLogsItOncePerResync(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID), runningPod("apps", "api", "docker.io/library/nginx@sha256:2222"))
	te.store.set(
		sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour)),
		sbomObject("docker.io/library/nginx@sha256:2222", "docker.io/library/nginx:1.27", helpersv1.Learning, te.clock.t.Add(-time.Hour)),
	)
	require.NoError(t, os.WriteFile(te.dt.keyFile, []byte("revoked-key"), 0600))
	require.NoError(t, te.resync(context.Background()))

	errs := te.drain()
	require.Len(t, errs, 2)
	assert.True(t, isAuthError(errs[0]))
	assert.Equal(t, int64(2), te.stats.failed.Load())
	assert.True(t, te.stats.authLogged.Load())

	te.stats.takeFields()
	assert.False(t, te.stats.authLogged.Load(), "the next resync logs it again")
}
