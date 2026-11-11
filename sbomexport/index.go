package sbomexport

import (
	"slices"
	"sync"
	"time"
)

// podEntry is what the index keeps of one running pod.
type podEntry struct {
	namespace string
	digests   []string
}

// index records, per image digest, the namespaces where a pod runs that
// image. A namespace stays listed for one grace period after its last such pod
// ended, so the image of a short Job is still exported once its SBOM is ready,
// which can take longer than the Job runs.
//
// It is safe for concurrent use.
type index struct {
	mu    sync.Mutex
	grace time.Duration
	now   func() time.Time

	pods  map[string]podEntry             // pod key → what it runs
	refs  map[string]map[string]int       // digest → namespace → running pods
	ended map[string]map[string]time.Time // digest → namespace → when its last pod ended
}

// newIndex returns an empty index that keeps ended namespaces for grace.
func newIndex(grace time.Duration, now func() time.Time) *index {
	return &index{
		grace: grace,
		now:   now,
		pods:  map[string]podEntry{},
		refs:  map[string]map[string]int{},
		ended: map[string]map[string]time.Time{},
	}
}

// setPod records that the pod with key runs digests in namespace, replacing
// what was recorded for it before. It returns the digests that now run in a
// namespace where they did not run before.
func (x *index) setPod(key, namespace string, digests []string) []string {
	x.mu.Lock()
	defer x.mu.Unlock()
	if len(digests) == 0 {
		x.removeLocked(key)
		return nil
	}
	digests = slices.Compact(slices.Sorted(slices.Values(digests)))
	// Count the new digests before dropping the old entry, so a digest the pod
	// keeps never falls to zero and is not reported as started again.
	var started []string
	for _, d := range digests {
		if x.incLocked(d, namespace) {
			started = append(started, d)
		}
	}
	x.removeLocked(key)
	x.pods[key] = podEntry{namespace: namespace, digests: digests}
	return started
}

// removePod forgets the pod with key.
func (x *index) removePod(key string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.removeLocked(key)
}

// replace rebuilds the index from a full list of running pods. An image that
// no longer runs in a namespace starts its grace period there.
func (x *index) replace(pods map[string]podEntry) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for key := range x.pods {
		if _, ok := pods[key]; !ok {
			x.removeLocked(key)
		}
	}
	for key, p := range pods {
		x.removeLocked(key)
		x.pods[key] = p
		for _, d := range p.digests {
			x.incLocked(d, p.namespace)
		}
	}
}

// namespaces returns, sorted, the namespaces where digest runs or ran less
// than a grace period ago.
func (x *index) namespaces(digest string) []string {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.pruneLocked()
	var out []string
	for ns := range x.refs[digest] {
		out = append(out, ns)
	}
	for ns := range x.ended[digest] {
		out = append(out, ns)
	}
	slices.Sort(out)
	return out
}

// digestsIn returns, sorted, the digests that run in ns or ran there less than
// a grace period ago.
func (x *index) digestsIn(ns string) []string {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.pruneLocked()
	var out []string
	for d, r := range x.refs {
		if r[ns] > 0 {
			out = append(out, d)
		}
	}
	for d, e := range x.ended {
		if _, ok := e[ns]; ok {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// digests returns every digest that namespaces would return a namespace for.
func (x *index) digests() []string {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.pruneLocked()
	var out []string
	for d := range x.refs {
		out = append(out, d)
	}
	for d := range x.ended {
		if _, running := x.refs[d]; !running {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return out
}

// removeLocked forgets the pod with key and uncounts its digests.
func (x *index) removeLocked(key string) {
	p, ok := x.pods[key]
	if !ok {
		return
	}
	delete(x.pods, key)
	for _, d := range p.digests {
		x.decLocked(d, p.namespace)
	}
}

// incLocked counts one more pod running digest in ns, and reports whether it
// is the first.
func (x *index) incLocked(digest, ns string) bool {
	if x.refs[digest] == nil {
		x.refs[digest] = map[string]int{}
	}
	x.refs[digest][ns]++
	if e := x.ended[digest]; e != nil {
		delete(e, ns)
		if len(e) == 0 {
			delete(x.ended, digest)
		}
	}
	return x.refs[digest][ns] == 1
}

// decLocked counts one less pod running digest in ns, and starts the grace
// period of ns when it was the last.
func (x *index) decLocked(digest, ns string) {
	r := x.refs[digest]
	if r == nil || r[ns] == 0 {
		return
	}
	r[ns]--
	if r[ns] > 0 {
		return
	}
	delete(r, ns)
	if len(r) == 0 {
		delete(x.refs, digest)
	}
	if x.ended[digest] == nil {
		x.ended[digest] = map[string]time.Time{}
	}
	x.ended[digest][ns] = x.now()
}

// pruneLocked drops the namespaces whose grace period is over.
func (x *index) pruneLocked() {
	now := x.now()
	for d, e := range x.ended {
		for ns, at := range e {
			if now.Sub(at) >= x.grace {
				delete(e, ns)
			}
		}
		if len(e) == 0 {
			delete(x.ended, d)
		}
	}
}
