package sbomexport

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
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
	"k8s.io/client-go/tools/cache"
)

const (
	redisImageID = "docker.io/library/redis@sha256:1111"
	redisTag     = "docker.io/library/redis:8"
	redisProject = "docker.io/library/redis"
)

// fakeStore serves SBOMSyft objects from memory; every document is the curl
// fixture.
type fakeStore struct {
	mu       sync.Mutex
	sboms    []*spdxv1beta1.SBOMSyft
	gets     int
	tooLarge bool   // answer every document read with a *tooLargeError
	limit    int64  // the limit of the last document read
	onList   func() // called after listSBOMs took its snapshot, without the lock
}

// listSBOMs returns the metadata of the objects set, then calls onList.
func (s *fakeStore) listSBOMs(context.Context) ([]sbomMeta, error) {
	s.mu.Lock()
	var out []sbomMeta
	for _, obj := range s.sboms {
		if m, ok := metaOf(obj); ok {
			out = append(out, m)
		}
	}
	hook := s.onList
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	return out, nil
}

// syftDocument counts the read and returns the curl fixture, or a
// *tooLargeError when tooLarge is set.
func (s *fakeStore) syftDocument(_ context.Context, _, _ string, limit int64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	s.limit = limit
	if s.tooLarge {
		return nil, &tooLargeError{read: limit + 1}
	}
	return curlSyftJSON, nil
}

func (s *fakeStore) set(sboms ...*spdxv1beta1.SBOMSyft) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sboms = sboms
}

// lastLimit returns the limit of the last document read.
func (s *fakeStore) lastLimit() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.limit
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

// newTestExporter returns an Exporter for cluster "cluster" with the default
// layout, a one-hour resync and kube-system excluded, over a fake
// Dependency-Track, a fake SBOM store and a fake clientset holding objects
// (pods and namespaces).
func newTestExporter(t *testing.T, objects ...runtime.Object) *testExporter {
	t.Helper()
	return newTestExporterWith(t, func(*Options) {}, objects...)
}

// newTestExporterWith is newTestExporter with options changed by change.
func newTestExporterWith(t *testing.T, change func(*Options), objects ...runtime.Object) *testExporter {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
	dt, srv, keyFile := newFakeDT(t, clock.now)
	store := &fakeStore{}
	client := k8sfake.NewClientset(objects...)
	opts := Options{
		URL:            srv.URL,
		APIKeyFile:     keyFile,
		Cluster:        "cluster",
		Layout:         defaultLayout,
		MaxSBOMSize:    10 << 20,
		ResyncInterval: time.Hour,
		SkipNamespace:  func(ns string) bool { return ns == "kube-system" },
	}
	change(&opts)
	e, err := newExporter(opts, client, store, srv.Client(), clock.now)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(e.queue.ShutDown)
	go e.namespaceInformer.Run(ctx.Done())
	require.True(t, cache.WaitForCacheSync(ctx.Done(), e.namespaceInformer.HasSynced))
	return &testExporter{Exporter: e, dt: dt, store: store, clock: clock, client: client}
}

// drain processes every queued item once, as Start's worker would, and
// returns the errors.
func (te *testExporter) drain() []error {
	var errs []error
	for te.queue.Len() > 0 {
		key, _ := te.queue.Get()
		var err error
		if ns, ok := strings.CutPrefix(key, moveKeyPrefix); ok {
			err = te.move(context.Background(), ns)
		} else {
			err = te.process(context.Background(), key)
		}
		if err != nil {
			errs = append(errs, err)
		}
		te.queue.Forget(key)
		te.queue.Done(key)
	}
	return errs
}

// updateNamespace replaces ns and waits until the exporter has queued its move.
func (te *testExporter) updateNamespace(t *testing.T, ns *corev1.Namespace) {
	t.Helper()
	seq := te.moveSeqForTest()
	_, err := te.client.CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return te.moveSeqForTest() > seq }, 5*time.Second, 10*time.Millisecond)
}

// moveSeqForTest returns how many namespace layout changes the exporter saw.
func (te *testExporter) moveSeqForTest() uint64 {
	te.mu.Lock()
	defer te.mu.Unlock()
	return te.moveSeq
}

func namespace(name string, annotations map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: annotations}}
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

// defaultLayout is the operator's default: <cluster>/<namespace>/<repository>:<tag>.
var defaultLayout = Layout{
	Root:    Collection{Name: "{{ .Cluster }}", Version: "current", Create: true},
	Parent:  Collection{Name: "{{ .Cluster }}/{{ .Namespace }}", Version: "current", Create: true},
	Name:    "{{ .Cluster }}/{{ .Namespace }}/{{ .Repository }}",
	Version: "{{ .Tag }}",
}

// New refuses options the exporter cannot run with.
func TestNewRejectsAnInvalidConfiguration(t *testing.T) {
	valid := Options{URL: "https://dtrack.example.com", APIKeyFile: "/etc/sbom-export/api-key", Cluster: "cluster", Layout: defaultLayout, MaxSBOMSize: 10 << 20, ResyncInterval: time.Hour}
	tt := []struct {
		name   string
		change func(*Options)
	}{
		{"no URL", func(o *Options) { o.URL = "" }},
		{"a URL without a scheme", func(o *Options) { o.URL = "dtrack.example.com" }},
		{"no API key file", func(o *Options) { o.APIKeyFile = "" }},
		{"a template that does not parse", func(o *Options) { o.Layout.Name = "{{ .Namespace" }},
		{"a template with an unknown field", func(o *Options) { o.Layout.Version = "{{ .Digest }}" }},
		{"no size limit", func(o *Options) { o.MaxSBOMSize = 0 }},
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
	namespace, parent, _ := te.dt.project("cluster/apps", "current")
	assert.Equal(t, "cluster", parent)
	assert.Equal(t, parentLogic, namespace.CollectionLogic)
	root, parent, _ := te.dt.project("cluster", "current")
	assert.Empty(t, parent)
	assert.Equal(t, rootLogic, root.CollectionLogic)
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

// Start exports the running images and returns once its context ends.
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

// node-agent rebuilds the SBOM of a running image in place when its own
// version changes: the creation time stays and the tool version changes.
func TestExporterSendsAnSBOMAgainWhenNodeAgentRebuiltIt(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID))
	sbom := sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour))
	sbom.Annotations[helpersv1.ToolVersionMetadataKey] = "v0.3.38"
	te.store.set(sbom)
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	require.Len(t, te.dt.takeUploads(), 1)
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	require.Empty(t, te.dt.takeUploads(), "same node-agent version: unchanged")

	rebuilt := sbom.DeepCopy()
	rebuilt.Annotations[helpersv1.ToolVersionMetadataKey] = "v0.3.39"
	te.store.set(rebuilt)
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	assert.Len(t, te.dt.takeUploads(), 1, "rebuilt by another node-agent version")

	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	assert.Empty(t, te.dt.takeUploads())
	p, _, _ := te.dt.project("cluster/apps/"+redisProject, "8")
	assert.Equal(t, "v0.3.39", te.dt.propertyForTest(p.UUID, toolVersionProperty))
}

// The tool version is recorded only after the upload, so a failed upload of a
// rebuilt SBOM is tried again instead of being taken as sent.
func TestExporterSendsARebuiltSBOMAgainAfterAFailedUpload(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID))
	sbom := sbomObject(redisImageID, redisTag, helpersv1.Learning, te.clock.t.Add(-time.Hour))
	sbom.Annotations[helpersv1.ToolVersionMetadataKey] = "v0.3.38"
	te.store.set(sbom)
	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	require.Len(t, te.dt.takeUploads(), 1)

	rebuilt := sbom.DeepCopy()
	rebuilt.Annotations[helpersv1.ToolVersionMetadataKey] = "v0.3.39"
	te.store.set(rebuilt)
	te.dt.mu.Lock()
	te.dt.failUploads = 1
	te.dt.mu.Unlock()
	require.NoError(t, te.resync(context.Background()))
	require.Len(t, te.drain(), 1)
	require.Empty(t, te.dt.takeUploads())

	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())
	assert.Len(t, te.dt.takeUploads(), 1)
}

// An SBOM that becomes ready while resync lists the SBOMSyft objects is not
// replaced by the older state the list returned.
func TestResyncKeepsAnSBOMThatBecameReadyWhileItListed(t *testing.T) {
	te := newTestExporter(t, runningPod("apps", "web", redisImageID))
	created := te.clock.t.Add(-time.Hour)
	te.store.set(sbomObject(redisImageID, redisTag, helpersv1.Initializing, created))
	te.store.onList = func() {
		te.ObserveSBOM(watch.Modified, sbomObject(redisImageID, redisTag, helpersv1.Learning, created))
	}

	require.NoError(t, te.resync(context.Background()))
	require.Empty(t, te.drain())

	assert.Len(t, te.dt.takeUploads(), 1)
}

// A pod that starts while resync lists the pods stays running instead of
// starting its grace period because the list missed it.
func TestResyncKeepsAPodThatStartedWhileItListed(t *testing.T) {
	te := newTestExporter(t)
	te.client.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		te.ObservePod(watch.Added, runningPod("apps", "web", redisImageID))
		return false, nil, nil
	})

	require.NoError(t, te.resync(context.Background()))

	te.clock.t = te.clock.t.Add(2 * time.Hour)
	assert.Equal(t, []string{"apps"}, te.running.namespaces(digestOf(redisImageID)))
}
