// Package sbomexport sends the SBOMs that node-agent stores (SBOMSyft
// objects) to Dependency-Track, one project per running image and namespace,
// and keeps them current as workloads change.
//
// By default the projects form a tree under the cluster:
//
//	<cluster> : current                          collection, adds up its namespaces
//	└── <cluster>/<namespace> : current          collection, adds up the latest version of each image
//	    └── <cluster>/<namespace>/<repository> : <tag>
//
// The names, versions and parents are templates (Layout), and a namespace can
// override them with annotations, for example to send its images under a
// project that already exists. The exporter only ever creates or changes
// projects it created itself, which it tags with "managed-by:kubescape".
//
// Two things trigger an export: SBOMWatch's events (an SBOM becomes ready, a
// pod starts with an image whose SBOM is ready), and a resync that compares
// every running image with Dependency-Track, so nothing is lost while
// Dependency-Track is unreachable or the operator restarts. An image is sent
// again only when its SBOMSyft is newer than the project's last BOM import.
package sbomexport

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/pager"
	"k8s.io/client-go/util/workqueue"
)

const (
	// A root adds up its children; a parent adds up the latest version of each
	// of its images, so the running tag is what counts.
	rootLogic   = "AGGREGATE_DIRECT_CHILDREN"
	parentLogic = "AGGREGATE_LATEST_VERSION_CHILDREN"

	// maxRetries bounds the retries of one item between two resyncs.
	maxRetries = 5

	requestTimeout = 2 * time.Minute

	// objectOverhead is room, on top of MaxSBOMSize, for the rest of an
	// SBOMSyft object around its syft document when the object is read.
	objectOverhead = 1 << 20

	// moveKeyPrefix marks queue items that move a namespace's projects after
	// its layout changed; every other item is an image digest.
	moveKeyPrefix = "namespace/"
)

// Options configures an Exporter.
type Options struct {
	// URL is the base URL of the Dependency-Track API server.
	URL string
	// APIKeyFile holds the API key; it is read on every request.
	APIKeyFile string
	// Cluster is the cluster name the layout templates see as .Cluster.
	Cluster string
	// Layout is where images go by default.
	Layout Layout
	// MaxSBOMSize is the largest SBOM, in bytes, that is converted. Converting
	// takes about nine times the SBOM's size in memory, so this bounds it.
	MaxSBOMSize int64
	// ResyncInterval is how often every running image is compared with
	// Dependency-Track. It is also how long an image counts as running in a
	// namespace after its last pod there ended.
	ResyncInterval time.Duration
	// SkipNamespace reports the namespaces whose images are not exported.
	SkipNamespace func(namespace string) bool
}

// validate checks the options that need no Dependency-Track call.
func (o Options) validate() error {
	u, err := url.Parse(o.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("sbomExport.dependencyTrack.url %q is not an http(s) URL", o.URL)
	}
	if o.APIKeyFile == "" {
		return errors.New("sbomExport.dependencyTrack.apiKeyFile is empty")
	}
	if o.MaxSBOMSize <= 0 {
		return fmt.Errorf("sbomExport.maxSBOMSize %d must be positive", o.MaxSBOMSize)
	}
	if o.ResyncInterval <= 0 {
		return fmt.Errorf("sbomExport.resyncInterval %s must be positive", o.ResyncInterval)
	}
	return nil
}

// Exporter sends SBOMs to Dependency-Track. Create it with New, feed it
// SBOMWatch's events with ObservePod and ObserveSBOM, and run it with Start.
type Exporter struct {
	opts    Options
	pods    kubernetes.Interface
	sboms   sbomStore
	dt      *dtClient
	layout  *layout
	running *index
	queue   workqueue.TypedRateLimitingInterface[string] // image digests and move keys

	namespaceInformer cache.SharedIndexInformer
	namespaceLister   corelisters.NamespaceLister

	mu           sync.Mutex
	sbomByImage  map[string]sbomMeta     // digest → its SBOMSyft
	projects     map[projectRef]string   // collection → uuid, emptied on every resync
	pendingMoves map[string]*pendingMove // namespace → where its move starts
	moveSeq      uint64                  // counts namespace layout changes
	logged       map[string]bool         // problems logged since the last resync
	// While resync lists, these hold the pods and SBOM digests that events
	// changed meanwhile. Their state from the events is newer than the
	// lists', so resync keeps it. nil when no resync is listing.
	touchedPods, touchedSBOMs map[string]bool

	stats stats
}

// New returns an Exporter that lists pods and watches namespaces with pods,
// and reads SBOMSyft objects with storage.
func New(opts Options, pods kubernetes.Interface, storage kssc.Interface) (*Exporter, error) {
	return newExporter(opts, pods, storageSBOMs{client: storage}, &http.Client{Timeout: requestTimeout}, time.Now)
}

// newExporter is New with the SBOM store, the HTTP client and the clock
// replaceable, for tests.
func newExporter(opts Options, pods kubernetes.Interface, sboms sbomStore, httpClient *http.Client, now func() time.Time) (*Exporter, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	l, err := newLayout(opts.Cluster, opts.Layout)
	if err != nil {
		return nil, fmt.Errorf("sbomExport.dependencyTrack layout: %w", err)
	}
	if opts.SkipNamespace == nil {
		opts.SkipNamespace = func(string) bool { return false }
	}
	informer := coreinformers.NewNamespaceInformer(pods, 0, cache.Indexers{})
	e := &Exporter{
		opts:    opts,
		pods:    pods,
		sboms:   sboms,
		dt:      &dtClient{baseURL: strings.TrimRight(opts.URL, "/"), apiKeyFile: opts.APIKeyFile, http: httpClient},
		layout:  l,
		running: newIndex(opts.ResyncInterval, now),
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](5*time.Second, 5*time.Minute),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "sbom-export"},
		),
		namespaceInformer: informer,
		namespaceLister:   corelisters.NewNamespaceLister(informer.GetIndexer()),
		sbomByImage:       map[string]sbomMeta{},
		projects:          map[projectRef]string{},
		pendingMoves:      map[string]*pendingMove{},
		logged:            map[string]bool{},
	}
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj any) {
			oldNS, oldOK := oldObj.(*corev1.Namespace)
			newNS, newOK := newObj.(*corev1.Namespace)
			if oldOK && newOK {
				e.namespaceChanged(oldNS, newNS)
			}
		},
	}); err != nil {
		return nil, err
	}
	return e, nil
}

// ObservePod records a pod event from SBOMWatch's pod watch, which only sees
// running pods: a pod that stops running arrives as Deleted.
func (e *Exporter) ObservePod(eventType watch.EventType, pod *corev1.Pod) {
	if e.opts.SkipNamespace(pod.Namespace) {
		return
	}
	key := pod.Namespace + "/" + pod.Name
	var ready []string
	e.mu.Lock()
	if e.touchedPods != nil {
		e.touchedPods[key] = true
	}
	switch eventType {
	case watch.Added, watch.Modified:
		for _, d := range e.running.setPod(key, pod.Namespace, runningDigests(pod)) {
			if m, ok := e.sbomByImage[d]; ok && m.ready() {
				ready = append(ready, d)
			}
		}
	case watch.Deleted:
		e.running.removePod(key)
	}
	e.mu.Unlock()
	for _, d := range ready {
		e.queue.Add(d)
	}
}

// ObserveSBOM records an SBOMSyft event from SBOMWatch.
func (e *Exporter) ObserveSBOM(eventType watch.EventType, obj *spdxv1beta1.SBOMSyft) {
	m, ok := metaOf(obj)
	if !ok {
		return
	}
	e.mu.Lock()
	if e.touchedSBOMs != nil {
		e.touchedSBOMs[m.digest] = true
	}
	switch eventType {
	case watch.Added, watch.Modified:
		e.sbomByImage[m.digest] = m
	case watch.Deleted:
		if cur, ok := e.sbomByImage[m.digest]; ok && cur.name == m.name && cur.namespace == m.namespace {
			delete(e.sbomByImage, m.digest)
		}
	}
	e.mu.Unlock()
	if eventType != watch.Deleted && m.ready() {
		e.queue.Add(m.digest)
	}
}

// pendingMove is a namespace whose layout changed: its projects still sit
// where from put them. seq tells whether another change came in since.
type pendingMove struct {
	from namespaceInfo
	seq  uint64
}

// namespaceChanged queues a move of the namespace's projects when a change of
// its labels or of its kubescape.io/dtrack-* annotations can change where its
// images go. The state before the first pending change is the one moved from.
func (e *Exporter) namespaceChanged(oldNS, newNS *corev1.Namespace) {
	if maps.Equal(oldNS.Labels, newNS.Labels) && maps.Equal(layoutAnnotations(oldNS), layoutAnnotations(newNS)) {
		return
	}
	e.mu.Lock()
	pm, ok := e.pendingMoves[newNS.Name]
	if !ok {
		pm = &pendingMove{from: infoOf(oldNS)}
		e.pendingMoves[newNS.Name] = pm
	}
	e.moveSeq++
	pm.seq = e.moveSeq
	e.mu.Unlock()
	e.queue.Add(moveKeyPrefix + newNS.Name)
}

// layoutAnnotations returns the kubescape.io/dtrack-* annotations of ns.
func layoutAnnotations(ns *corev1.Namespace) map[string]string {
	out := map[string]string{}
	for k, v := range ns.Annotations {
		if strings.HasPrefix(k, "kubescape.io/dtrack-") {
			out[k] = v
		}
	}
	return out
}

// infoOf copies what the layout needs from ns.
func infoOf(ns *corev1.Namespace) namespaceInfo {
	return namespaceInfo{name: ns.Name, labels: maps.Clone(ns.Labels), annotations: maps.Clone(ns.Annotations)}
}

// namespaceInfo returns the namespace's labels and annotations, or none when
// it is not known (yet).
func (e *Exporter) namespaceInfo(name string) namespaceInfo {
	if ns, err := e.namespaceLister.Get(name); err == nil {
		return infoOf(ns)
	}
	return namespaceInfo{name: name}
}

// Start exports until ctx is done: it watches namespaces, one worker drains
// the queue, and a resync runs now and every ResyncInterval.
func (e *Exporter) Start(ctx context.Context) {
	go func() {
		<-ctx.Done()
		e.queue.ShutDown()
	}()
	go e.namespaceInformer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), e.namespaceInformer.HasSynced) {
		return
	}
	go e.work(ctx)

	logger.L().Info("starting SBOM export to Dependency-Track",
		helpers.String("url", e.opts.URL),
		helpers.String("resyncInterval", e.opts.ResyncInterval.String()))

	ticker := time.NewTicker(e.opts.ResyncInterval)
	defer ticker.Stop()
	for {
		if err := e.resync(ctx); err != nil && ctx.Err() == nil {
			logger.L().Ctx(ctx).Error("SBOM export resync failed, retrying at the next one", helpers.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// work drains the queue: image digests are exported, namespace keys moved.
// A failed item is retried with backoff, then left to the next resync.
func (e *Exporter) work(ctx context.Context) {
	for {
		key, shutdown := e.queue.Get()
		if shutdown {
			return
		}
		var err error
		if ns, ok := strings.CutPrefix(key, moveKeyPrefix); ok {
			err = e.move(ctx, ns)
		} else {
			err = e.process(ctx, key)
		}
		switch {
		case err == nil:
			e.queue.Forget(key)
		case e.queue.NumRequeues(key) < maxRetries && ctx.Err() == nil:
			e.queue.AddRateLimited(key)
		default:
			e.queue.Forget(key)
			logger.L().Ctx(ctx).Warning("giving up on this SBOM export item until the next resync",
				helpers.String("item", key), helpers.Error(err))
		}
		e.queue.Done(key)
	}
}

// resync rebuilds the running index from one paged list of running pods and
// the SBOM metadata from one list of SBOMSyft objects, keeping what events
// changed while it listed, then queues the pending moves and every running
// image. If either list fails, nothing changes.
func (e *Exporter) resync(ctx context.Context) error {
	logger.L().Info("SBOM export since the last resync", e.stats.takeFields()...)
	e.mu.Lock()
	e.logged = map[string]bool{}
	e.touchedPods, e.touchedSBOMs = map[string]bool{}, map[string]bool{}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.touchedPods, e.touchedSBOMs = nil, nil
		e.mu.Unlock()
	}()

	pods := map[string]podEntry{}
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return e.pods.CoreV1().Pods("").List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{FieldSelector: "status.phase=Running"}, func(obj runtime.Object) error {
		pod := obj.(*corev1.Pod)
		if e.opts.SkipNamespace(pod.Namespace) {
			return nil
		}
		if digests := runningDigests(pod); len(digests) > 0 {
			pods[pod.Namespace+"/"+pod.Name] = podEntry{namespace: pod.Namespace, digests: digests}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("list running pods: %w", err)
	}
	sboms, err := e.sboms.listSBOMs(ctx)
	if err != nil {
		return fmt.Errorf("list SBOMSyft objects: %w", err)
	}

	byImage := make(map[string]sbomMeta, len(sboms))
	for _, m := range sboms {
		byImage[m.digest] = m
	}
	e.mu.Lock()
	e.running.replace(pods, e.touchedPods)
	for d := range e.touchedSBOMs {
		if m, ok := e.sbomByImage[d]; ok {
			byImage[d] = m
		} else {
			delete(byImage, d)
		}
	}
	e.touchedPods, e.touchedSBOMs = nil, nil
	e.sbomByImage = byImage
	e.projects = map[projectRef]string{}
	moves := slices.Sorted(maps.Keys(e.pendingMoves))
	e.mu.Unlock()

	// Moves go first, so an image is moved before it is exported again.
	for _, ns := range moves {
		e.queue.Add(moveKeyPrefix + ns)
	}
	for _, d := range e.running.digests() {
		e.queue.Add(d)
	}
	return nil
}

// sbom returns the metadata of digest's SBOMSyft, if one is known.
func (e *Exporter) sbom(digest string) (sbomMeta, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	m, ok := e.sbomByImage[digest]
	return m, ok
}

// result is what exporting one image to one place did.
type result int

const (
	resultSent result = iota
	resultUnchanged
	resultConflict // the project belongs to another image or was not created by the exporter
	resultSkipped  // the layout cannot be resolved, or a project it names is missing
	resultTooLarge
)

// process exports the SBOM of one image to the project of every namespace it
// runs in. One namespace failing does not stop the others; the image is
// retried as a whole, and namespaces already done are then only looked up.
func (e *Exporter) process(ctx context.Context, digest string) error {
	namespaces := e.running.namespaces(digest)
	if len(namespaces) == 0 {
		return nil
	}
	m, ok := e.sbom(digest)
	if !ok || !m.ready() {
		e.stats.skipped.Add(1)
		return nil
	}
	if m.size > e.opts.MaxSBOMSize {
		e.stats.tooLarge.Add(1)
		e.logTooLarge(ctx, m, m.size)
		return nil
	}
	repository, tag := splitRef(m.imageTag)
	var bom []byte // converted once, for every namespace
	var errs []error
	for _, ns := range namespaces {
		p, err := e.layout.resolve(e.namespaceInfo(ns), repository, tag)
		if err != nil {
			e.stats.skippedLayout.Add(1)
			e.logOnce(ctx, "layout/"+ns, "cannot resolve the Dependency-Track layout of this namespace, skipping its images",
				helpers.String("namespace", ns), helpers.Error(err))
			continue
		}
		res, err := e.exportTo(ctx, m, ns, p, &bom)
		switch {
		case err != nil:
			e.stats.failed.Add(1)
			e.logFailure(ctx, err, m.imageTag, p.name, p.version)
			errs = append(errs, err)
		case res == resultSent:
			e.stats.sent.Add(1)
			logger.L().Info("sent SBOM to Dependency-Track", helpers.String("project", p.name), helpers.String("version", p.version))
		case res == resultUnchanged:
			e.stats.unchanged.Add(1)
		case res == resultConflict:
			e.stats.conflicts.Add(1)
		case res == resultSkipped:
			e.stats.skippedLayout.Add(1)
		case res == resultTooLarge:
			e.stats.tooLarge.Add(1)
			return nil
		}
	}
	return errors.Join(errs...)
}

// exportTo makes p's project hold m's SBOM as its latest version. An image
// whose project imported a BOM no older than its SBOMSyft, built by the same
// node-agent version, is only marked latest. It never uploads to a project it
// did not create, nor to one that holds the BOM of another image that still
// runs. Before it uploads, it creates a missing project and records m's digest
// on it, so a second image can never take a project whose upload went through
// but whose owner was not recorded.
func (e *Exporter) exportTo(ctx context.Context, m sbomMeta, ns string, p placement, bom *[]byte) (result, error) {
	target, err := e.dt.lookup(ctx, p.name, p.version)
	if err != nil {
		return 0, err
	}
	owner, sentVersion, parentUUID := "", "", ""
	if target != nil {
		if !target.managed() {
			e.logOnce(ctx, "conflict/"+p.name+":"+p.version, "a Dependency-Track project with this name and version exists and was not created by Kubescape, skipping the image",
				helpers.String("project", p.name), helpers.String("version", p.version), helpers.String("image", m.imageTag), helpers.String("namespace", ns))
			return resultConflict, nil
		}
		// Resolve the parent of an existing project too, so a collection the
		// exporter created follows a changed root.
		if _, err := e.parent(ctx, p); err != nil {
			var missing *missingProjectError
			if !errors.As(err, &missing) {
				return 0, err
			}
			e.logMissing(ctx, missing, ns)
		}
		props, err := e.dt.properties(ctx, target.UUID)
		if err != nil {
			return 0, err
		}
		owner, sentVersion = props[digestProperty], props[toolVersionProperty]
		if owner != "" && owner != m.digest && len(e.running.namespaces(owner)) > 0 {
			e.logOnce(ctx, "conflict/"+p.name+":"+p.version, "two running images map to the same Dependency-Track project and version, skipping the second; include the repository in the project name template",
				helpers.String("project", p.name), helpers.String("version", p.version), helpers.String("image", m.imageTag), helpers.String("namespace", ns),
				helpers.String("ownerDigest", owner), helpers.String("digest", m.digest))
			return resultConflict, nil
		}
		// node-agent rebuilds an SBOM in place when its version changes, so
		// the creation time alone does not show a new document.
		rebuilt := m.toolVersion != "" && m.toolVersion != sentVersion
		if owner == m.digest && !rebuilt && !target.LastBOMImport.Time().Before(m.created) {
			if !target.IsLatest {
				if err := e.dt.patch(ctx, target.UUID, map[string]any{"isLatest": true}); err != nil {
					return 0, err
				}
			}
			return resultUnchanged, nil
		}
	} else {
		parentUUID, err = e.parent(ctx, p)
		var missing *missingProjectError
		if errors.As(err, &missing) {
			e.logMissing(ctx, missing, ns)
			return resultSkipped, nil
		}
		if err != nil {
			return 0, err
		}
	}

	if *bom == nil {
		doc, err := e.sboms.syftDocument(ctx, m.namespace, m.name, e.opts.MaxSBOMSize+objectOverhead)
		var tooLarge *tooLargeError
		if errors.As(err, &tooLarge) {
			e.logTooLarge(ctx, m, tooLarge.read)
			return resultTooLarge, nil
		}
		if err != nil {
			return 0, err
		}
		if int64(len(doc)) > e.opts.MaxSBOMSize {
			e.logTooLarge(ctx, m, int64(len(doc)))
			return resultTooLarge, nil
		}
		if *bom, err = toCycloneDX(doc); err != nil {
			return 0, fmt.Errorf("convert SBOMSyft %s/%s: %w", m.namespace, m.name, err)
		}
	}
	if target == nil {
		if target, err = e.dt.createProject(ctx, p.name, p.version, parentUUID); err != nil {
			return 0, err
		}
	}
	if owner != m.digest {
		if err := e.dt.setProperty(ctx, target.UUID, digestProperty, m.digest); err != nil {
			return 0, err
		}
	}
	if err := e.dt.uploadBOM(ctx, p.name, p.version, *bom); err != nil {
		return 0, err
	}
	// Marked latest only now that its BOM is in: a failed upload leaves the
	// previous latest version counted by the namespace collection, which only
	// counts the latest version of each image. The upload itself doesn't mark
	// a project latest (see uploadBOM).
	if !target.IsLatest {
		if err := e.dt.patch(ctx, target.UUID, map[string]any{"isLatest": true}); err != nil {
			return 0, err
		}
	}
	// Recorded after the upload: when this fails, the next pass sends the SBOM
	// again rather than skip a document Dependency-Track never got.
	if m.toolVersion != "" && m.toolVersion != sentVersion {
		if err := e.dt.setProperty(ctx, target.UUID, toolVersionProperty, m.toolVersion); err != nil {
			return 0, err
		}
	}
	return resultSent, nil
}

// logMissing logs, once per resync, a project the layout names that is
// missing and may not be created.
func (e *Exporter) logMissing(ctx context.Context, missing *missingProjectError, ns string) {
	e.logOnce(ctx, "missing/"+missing.ref.String(), "a Dependency-Track project the layout names does not exist and may not be created, skipping the namespace's images",
		helpers.String("project", missing.ref.String()), helpers.String("reason", missing.reason), helpers.String("namespace", ns))
}

// missingProjectError is a project the layout names that does not exist and
// may not be created.
type missingProjectError struct {
	ref    projectRef
	reason string
}

// Error describes the missing project.
func (e *missingProjectError) Error() string {
	return fmt.Sprintf("project %s %s", e.ref, e.reason)
}

// parent returns the uuid of p's parent, creating it, and the root above it,
// when they are missing and may be created.
func (e *Exporter) parent(ctx context.Context, p placement) (string, error) {
	return e.collection(ctx, p.parent, p.parentCreate, parentLogic, func() (string, error) {
		return e.collection(ctx, p.root, p.rootCreate, rootLogic, nil)
	})
}

// collection returns the uuid of the collection project ref names. A missing
// one is created, under the project parentOf returns, only when create allows
// it. A collection the exporter created keeps its collection logic and, when
// parentOf is given, its place under the project parentOf returns, so a
// changed root takes the collection along. Other collections are never
// changed.
func (e *Exporter) collection(ctx context.Context, ref projectRef, create bool, logic string, parentOf func() (string, error)) (string, error) {
	e.mu.Lock()
	uuid, ok := e.projects[ref]
	e.mu.Unlock()
	if ok {
		return uuid, nil
	}

	p, err := e.dt.find(ctx, ref)
	if err != nil {
		return "", err
	}
	switch {
	case p != nil && p.managed():
		if err := e.reconcileCollection(ctx, p, logic, parentOf); err != nil {
			return "", err
		}
	case p != nil:
	case ref.uuid != "":
		return "", &missingProjectError{ref: ref, reason: "does not exist; a project named by UUID is never created"}
	case !create:
		return "", &missingProjectError{ref: ref, reason: "does not exist and create is false"}
	default:
		parentUUID := ""
		if parentOf != nil {
			if parentUUID, err = parentOf(); err != nil {
				return "", err
			}
		}
		if p, err = e.dt.createCollection(ctx, ref.name, ref.version, parentUUID, logic); err != nil {
			return "", err
		}
		logger.L().Info("created Dependency-Track collection project", helpers.String("project", ref.String()), helpers.String("collectionLogic", logic))
	}

	e.mu.Lock()
	e.projects[ref] = p.UUID
	e.mu.Unlock()
	return p.UUID, nil
}

// reconcileCollection sets the collection logic of a collection the exporter
// created and, when parentOf is given, moves it under the project parentOf
// returns. When that project is missing and may not be created, the
// collection stays where it is.
func (e *Exporter) reconcileCollection(ctx context.Context, p *project, logic string, parentOf func() (string, error)) error {
	fields := map[string]any{}
	if p.CollectionLogic != logic {
		fields["collectionLogic"] = logic
	}
	if parentOf != nil {
		want, err := parentOf()
		var missing *missingProjectError
		switch {
		case errors.As(err, &missing):
			e.logMissing(ctx, missing, "")
		case err != nil:
			return err
		default:
			// a lookup by name leaves the parent out; a GET by UUID has it
			full, err := e.dt.getByUUID(ctx, p.UUID)
			if err != nil {
				return err
			}
			if full != nil && (full.Parent == nil || full.Parent.UUID != want) {
				fields["parent"] = map[string]string{"uuid": want}
			}
		}
	}
	if len(fields) == 0 {
		return nil
	}
	// Dependency-Track sets the collection logic to NONE on a PATCH that
	// leaves it out, so moving a collection sends its logic too.
	body := maps.Clone(fields)
	body["collectionLogic"] = logic
	if err := e.dt.patch(ctx, p.UUID, body); err != nil {
		return err
	}
	logger.L().Info("updated Dependency-Track collection project", helpers.String("project", p.Name+":"+p.Version), helpers.Interface("changes", fields))
	return nil
}

// move moves the projects of the images running in ns from where the
// namespace's previous labels and annotations put them to where the current
// ones do, so their history in Dependency-Track moves with them. It moves only
// projects the exporter created, and never onto a project that exists; the
// images are then exported as usual. When only the root changes, it moves the
// namespace's parent collection, also when none of its images can be exported.
// A move whose destination is missing and may not be created stays pending and
// is tried again at every resync. A change made while the operator was not
// running is not seen, so those images start new projects.
func (e *Exporter) move(ctx context.Context, ns string) error {
	e.mu.Lock()
	pm, ok := e.pendingMoves[ns]
	var before namespaceInfo
	var seq uint64
	if ok {
		before, seq = pm.from, pm.seq
	}
	// The collection cache is dropped, so the move and the exports after it
	// find, and reconcile, the collections of the new layout.
	e.projects = map[projectRef]string{}
	e.mu.Unlock()
	if !ok {
		return nil
	}
	now := e.namespaceInfo(ns)
	digests := e.running.digestsIn(ns)
	parents := map[projectRef]bool{} // parents whose root was handled
	waiting := false
	var errs []error
	for _, d := range digests {
		m, ok := e.sbom(d)
		if !ok {
			continue
		}
		repository, tag := splitRef(m.imageTag)
		from, err1 := e.layout.resolve(before, repository, tag)
		to, err2 := e.layout.resolve(now, repository, tag)
		if err1 != nil || err2 != nil {
			continue
		}
		var done bool
		var err error
		if from.name == to.name && from.version == to.version && from.parent == to.parent {
			if parents[to.parent] {
				continue
			}
			parents[to.parent] = true
			done, err = e.moveParent(ctx, ns, from, to)
		} else {
			done, err = e.moveProject(ctx, ns, from, to)
		}
		switch {
		case err != nil:
			errs = append(errs, err)
		case !done:
			waiting = true
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	// A waiting move keeps the state it started from. Otherwise a change that
	// came in meanwhile moves on from where this one ended.
	e.mu.Lock()
	if cur, ok := e.pendingMoves[ns]; ok && !waiting {
		if cur.seq == seq {
			delete(e.pendingMoves, ns)
		} else {
			cur.from = now
		}
	}
	e.mu.Unlock()
	for _, d := range digests {
		e.queue.Add(d)
	}
	return nil
}

// moveProject moves the exporter's project at from to to: its name, version
// and parent. When only the parent changes, the project found at to is the
// same one, and only its parent changes. A different project at to is left
// alone. It reports false when to's parent, or its root, is missing and may
// not be created, so the move waits.
func (e *Exporter) moveProject(ctx context.Context, ns string, from, to placement) (bool, error) {
	p, err := e.dt.lookup(ctx, from.name, from.version)
	if err != nil || p == nil || !p.managed() {
		return true, err
	}
	target, err := e.dt.lookup(ctx, to.name, to.version)
	if err != nil || (target != nil && target.UUID != p.UUID) {
		return true, err
	}
	parentUUID, err := e.parent(ctx, to)
	var missing *missingProjectError
	if errors.As(err, &missing) {
		e.logMissing(ctx, missing, ns)
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if target != nil {
		// Only the parent changes. An earlier try of a waiting move may have
		// moved this project already; a lookup by name leaves the parent out.
		full, err := e.dt.getByUUID(ctx, p.UUID)
		if err != nil {
			return false, err
		}
		if full != nil && full.Parent != nil && full.Parent.UUID == parentUUID {
			return true, nil
		}
	}
	if err := e.dt.patch(ctx, p.UUID, map[string]any{"name": to.name, "version": to.version, "parent": map[string]string{"uuid": parentUUID}}); err != nil {
		return false, err
	}
	e.stats.moved.Add(1)
	logger.L().Info("moved Dependency-Track project after the namespace's layout changed",
		helpers.String("namespace", ns), helpers.String("from", from.name+":"+from.version), helpers.String("to", to.name+":"+to.version))
	return true, nil
}

// moveParent moves to's parent collection under to's root when only the root
// changed. Exports move it too, but only for images they can export, so a
// namespace whose SBOMs are all too large or not ready would keep its parent
// under the old root. A parent the exporter did not create, or none yet, is
// left alone. It reports false when the root is missing and may not be
// created, so the move waits.
func (e *Exporter) moveParent(ctx context.Context, ns string, from, to placement) (bool, error) {
	if from.root == to.root && from.rootCreate == to.rootCreate {
		return true, nil
	}
	parent, err := e.dt.find(ctx, to.parent)
	if err != nil || parent == nil || !parent.managed() {
		return true, err
	}
	rootUUID, err := e.collection(ctx, to.root, to.rootCreate, rootLogic, nil)
	var missing *missingProjectError
	if errors.As(err, &missing) {
		e.logMissing(ctx, missing, ns)
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, e.reconcileCollection(ctx, parent, parentLogic, func() (string, error) { return rootUUID, nil })
}

// logTooLarge logs, once per resync, that the SBOM of m is over MaxSBOMSize.
func (e *Exporter) logTooLarge(ctx context.Context, m sbomMeta, size int64) {
	e.logOnce(ctx, "too-large/"+m.digest, "SBOM is larger than sbomExport.maxSBOMSize, skipping it",
		helpers.String("image", m.imageTag), helpers.Int("size", int(size)), helpers.Int("maxSBOMSize", int(e.opts.MaxSBOMSize)))
}

// logOnce logs a warning the first time key comes up after a resync, so a
// problem that affects every image is logged once, not once per image.
func (e *Exporter) logOnce(ctx context.Context, key, msg string, fields ...helpers.IDetails) {
	e.mu.Lock()
	seen := e.logged[key]
	e.logged[key] = true
	e.mu.Unlock()
	if !seen {
		logger.L().Ctx(ctx).Warning(msg, fields...)
	}
}

// logFailure logs a failed export of image, at project name:version. A refused
// API key fails every image the same way, so it is logged once per resync.
func (e *Exporter) logFailure(ctx context.Context, err error, image, name, version string) {
	fields := []helpers.IDetails{helpers.String("image", image), helpers.String("project", name), helpers.String("version", version), helpers.Error(err)}
	if isAuthError(err) {
		if e.stats.authLogged.Swap(true) {
			return
		}
		fields = append(fields, helpers.String("hint", "the API key's team needs VIEW_PORTFOLIO, BOM_UPLOAD and PORTFOLIO_MANAGEMENT (on 5.x: PORTFOLIO_MANAGEMENT_CREATE and PORTFOLIO_MANAGEMENT_UPDATE); with portfolio access control on, access to the projects the layout names"))
	}
	logger.L().Ctx(ctx).Error("failed to export SBOM to Dependency-Track", fields...)
}

// stats counts what the exporter did between two resyncs.
type stats struct {
	sent, unchanged, skipped, tooLarge, conflicts, skippedLayout, moved, failed atomic.Int64
	authLogged                                                                  atomic.Bool // a refused API key was logged
}

// takeFields returns the counts as log fields and resets them.
func (s *stats) takeFields() []helpers.IDetails {
	s.authLogged.Store(false)
	return []helpers.IDetails{
		helpers.Int("sent", int(s.sent.Swap(0))),
		helpers.Int("unchanged", int(s.unchanged.Swap(0))),
		helpers.Int("skippedNoReadySBOM", int(s.skipped.Swap(0))),
		helpers.Int("skippedTooLarge", int(s.tooLarge.Swap(0))),
		helpers.Int("conflicts", int(s.conflicts.Swap(0))),
		helpers.Int("skippedLayout", int(s.skippedLayout.Swap(0))),
		helpers.Int("moved", int(s.moved.Swap(0))),
		helpers.Int("failed", int(s.failed.Swap(0))),
	}
}
