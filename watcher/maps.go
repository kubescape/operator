package watcher

import (
	"sync"

	sets "github.com/deckarep/golang-set/v2"
)

type wlidSet sets.Set[string]

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

func (m *imageIDWLIDMap) init() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wlidsByImageID = make(map[string]wlidSet)
}

// Set sets a given list of WLIDs for the provided image ID
func (m *imageIDWLIDMap) Set(imageID string, wlids wlidSet) {
	if m.wlidsByImageID == nil {
		m.init()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wlidsByImageID[imageID] = wlids
}

// Get returns a list of WLIDs for the provided imageID
func (m *imageIDWLIDMap) Get(imageID string) (wlidSet, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.wlidsByImageID[imageID]
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
