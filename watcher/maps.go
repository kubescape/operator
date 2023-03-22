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

// imageIDWLIDMap maps an Image ID to a list of WLIDs that are running it
type imageIDWLIDMap struct {
	wlidsByImageID map[string]wlidSet
	mu             sync.RWMutex
}

// NewImageIDWLIDsMap returns a new ImageID to WLID map
func NewImageIDWLIDsMap() *imageIDWLIDMap {
	return &imageIDWLIDMap{}
}

// NewImageIDWLIDsMapFrom returns a new ImageID to WLID map populated from a map of starting values
func NewImageIDWLIDsMapFrom(startingValues map[string][]string) *imageIDWLIDMap {
	resultingMap := make(map[string]wlidSet)

	for k, v := range startingValues {
		resultingMap[k] = NewWLIDSet(v...)
	}

	return &imageIDWLIDMap{wlidsByImageID: resultingMap}
}

// init initializes the underlying map of WLIDs
//
// NOT THREAD-SAFE! Assumes that the caller is holding a Write lock.
func (m *imageIDWLIDMap) init() {
	m.wlidsByImageID = make(map[string]wlidSet)
}

// setUnsafe sets a given list of WLIDs for the provided image ID
//
// NOT THREAD SAFE! Assumes that the caller is holding a Write lock.
func (m *imageIDWLIDMap) setUnsafe(imageID string, wlids wlidSet) {
	if m.wlidsByImageID == nil {
		m.init()
	}
	m.wlidsByImageID[imageID] = wlids
}

// StoreSet sets a given set of WLIDs for the provided image ID
func (m *imageIDWLIDMap) StoreSet(imageID string, wlids wlidSet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setUnsafe(imageID, wlids)
}

// getUnsafe returns the wlidSet at given image ID
//
// NOT THREAD SAFE! Assumes the caller is holding a Read lock.
func (m *imageIDWLIDMap) getUnsafe(imageID string) (wlidSet, bool) {
	val, ok := m.wlidsByImageID[imageID]
	return val, ok

}

// Load returns a slice of WLIds for a given Image ID
//
// As the result is logically a set, it does not guarantee a stable order of its elements
func (m *imageIDWLIDMap) Load(imageID string) ([]string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	val, ok := m.getUnsafe(imageID)
	if ok {
		return val.ToSlice(), ok
	}
	return nil, ok
}

// LoadSet returns a copy of a set of WLIDs for the provided imageID
//
// This method returns a copy so that callers will not be able to modify the
// underlying data structures. To modify the map, use its public methods.
func (m *imageIDWLIDMap) LoadSet(imageID string) (wlidSet, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	val, ok := m.getUnsafe(imageID)
	if !ok {
		return val, ok
	}
	return val.Clone(), ok
}

// Clear clears the map and sets it to an empty map
func (m *imageIDWLIDMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wlidsByImageID = map[string]wlidSet{}
}

// Add adds a given list of WLIDs to a provided imageID
func (m *imageIDWLIDMap) Add(imageID string, wlids ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existingWlids, ok := m.getUnsafe(imageID)
	if !ok {
		wlidSet := NewWLIDSet(wlids...)
		m.setUnsafe(imageID, wlidSet)

	} else {
		existingWlids.Append(wlids...)
	}
}

// Range calls f sequentially over the contents of the map, using WLIDs as slice of string
func (m *imageIDWLIDMap) Range(f func(imageID string, wlids []string) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for imageID, wlids := range m.wlidsByImageID {
		if !f(imageID, wlids.ToSlice()) {
			return
		}
	}
}

// Map returns a map that corresponds to the state of the data structure at the moment of the call
//
// As each value is logically a set, the method does not guarantee a stable order of its elements
func (m *imageIDWLIDMap) Map() map[string][]string {
	res := map[string][]string{}

	m.Range(func(imageID string, wlids []string) bool {
		res[imageID] = wlids
		return true
	})
	return res
}
