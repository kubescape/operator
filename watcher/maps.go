package watcher

import (
	"sync"
)

// imageIDWLIDMap maps an Image ID to a list of WLIDs that are running it
type imageIDWLIDMap struct {
	wlidsByImageID map[string][]string
	mu             sync.RWMutex
}

// NewImageIDWLIDsMap returns a new ImageID to WLID map
func NewImageIDWLIDsMap() *imageIDWLIDMap {
	return &imageIDWLIDMap{}
}

func (m *imageIDWLIDMap) init() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wlidsByImageID = make(map[string][]string)
}

// Set sets a given list of WLIDs for the provided image ID
func (m *imageIDWLIDMap) Set(imageID string, wlids []string) {
	if m.wlidsByImageID == nil {
		m.init()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wlidsByImageID[imageID] = wlids
}

// Get returns a list of WLIDs for the provided imageID
func (m *imageIDWLIDMap) Get(imageID string) ([]string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.wlidsByImageID[imageID]
	return val, ok
}

// Clear clears the map and sets it to an empty map
func (m *imageIDWLIDMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wlidsByImageID = map[string][]string{}
}
