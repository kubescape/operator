package watcher

import (
	"sync"

	sets "github.com/deckarep/golang-set/v2"
)

// wlidSet is a set of WLIDs.
//
// Uses a thread-safe implementation of sets.
type wlidSet sets.Set[string]

// NewWLIDSet returns a new empty set of WLIDs
func NewWLIDSet(values ...string) wlidSet {
	return sets.NewSet(values...)
}

// imageHashWLIDMap maps an Image Hash to a list of WLIDs that are running it
type imageHashWLIDMap struct {
	wlidsByImageHash map[string]wlidSet
	mu               sync.RWMutex
}

// NewImageHashWLIDsMap returns a new Image Hash to WLID map
func NewImageHashWLIDsMap() *imageHashWLIDMap {
	return &imageHashWLIDMap{}
}

// NewImageHashWLIDsMapFrom returns a new Image Hash to WLID map populated from a map of starting values
func NewImageHashWLIDsMapFrom(startingValues map[string][]string) *imageHashWLIDMap {
	resultingMap := make(map[string]wlidSet)

	for k, v := range startingValues {
		resultingMap[k] = NewWLIDSet(v...)
	}

	return &imageHashWLIDMap{wlidsByImageHash: resultingMap}
}

// init initializes the underlying map of WLIDs
//
// NOT THREAD-SAFE! Assumes that the caller is holding a Write lock.
func (m *imageHashWLIDMap) init() {
	m.wlidsByImageHash = make(map[string]wlidSet)
}

// setUnsafe sets a given list of WLIDs for the provided image hash
//
// NOT THREAD SAFE! Assumes that the caller is holding a Write lock.
func (m *imageHashWLIDMap) setUnsafe(imageHash string, wlids wlidSet) {
	if m.wlidsByImageHash == nil {
		m.init()
	}
	m.wlidsByImageHash[imageHash] = wlids
}

// StoreSet sets a given set of WLIDs for the provided image hash
func (m *imageHashWLIDMap) StoreSet(imageHash string, wlids wlidSet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setUnsafe(imageHash, wlids)
}

// getUnsafe returns the wlidSet at given image hash
//
// NOT THREAD SAFE! Assumes the caller is holding a Read lock.
func (m *imageHashWLIDMap) getUnsafe(imageHash string) (wlidSet, bool) {
	val, ok := m.wlidsByImageHash[imageHash]
	return val, ok

}

// Load returns a slice of WLIds for a given Image Hash
//
// As the result is logically a set, it does not guarantee a stable order of its elements
func (m *imageHashWLIDMap) Load(imageHash string) ([]string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	val, ok := m.getUnsafe(imageHash)
	if ok {
		return val.ToSlice(), ok
	}
	return nil, ok
}

// LoadSet returns a copy of a set of WLIDs for the provided image hash
//
// This method returns a copy so that callers will not be able to modify the
// underlying data structures. To modify the map, use its public methods.
func (m *imageHashWLIDMap) LoadSet(imageHash string) (wlidSet, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	val, ok := m.getUnsafe(imageHash)
	if !ok {
		return val, ok
	}
	return val.Clone(), ok
}

// Clear clears the map and sets it to an empty map
func (m *imageHashWLIDMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wlidsByImageHash = map[string]wlidSet{}
}

// Add adds a given list of WLIDs to a provided image hash
func (m *imageHashWLIDMap) Add(imageHash string, wlids ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existingWlids, ok := m.getUnsafe(imageHash)
	if !ok {
		wlidSet := NewWLIDSet(wlids...)
		m.setUnsafe(imageHash, wlidSet)

	} else {
		existingWlids.Append(wlids...)
	}
}

// Range calls f sequentially over the contents of the map, using WLIDs as slice of string
func (m *imageHashWLIDMap) Range(f func(imageHash string, wlids []string) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for imageHash, wlids := range m.wlidsByImageHash {
		if !f(imageHash, wlids.ToSlice()) {
			return
		}
	}
}

// Map returns a map that corresponds to the state of the data structure at the moment of the call
//
// As each value is logically a set, the method does not guarantee a stable order of its elements
func (m *imageHashWLIDMap) Map() map[string][]string {
	res := map[string][]string{}

	m.Range(func(imageHash string, wlids []string) bool {
		res[imageHash] = wlids
		return true
	})
	return res
}
