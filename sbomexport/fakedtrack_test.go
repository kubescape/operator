package sbomexport

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testAPIKey = "test-api-key"

// fakeDT is an in-memory Dependency-Track that serves the calls dtClient
// makes: project lookup, create, patch, and BOM upload with autoCreate.
type fakeDT struct {
	mu       sync.Mutex
	now      func() time.Time
	projects map[string]*project // "name:version" → project
	parents  map[string]string   // project uuid → parent uuid
	uploads  []string            // "name:version" of every BOM upload
	nextID   int
	fail     int    // answer the next fail requests with 503
	keyFile  string // holds testAPIKey
}

// newFakeDT starts a fakeDT and returns it with an API key file holding
// testAPIKey.
func newFakeDT(t *testing.T, now func() time.Time) (*fakeDT, *httptest.Server, string) {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "api-key")
	if err := os.WriteFile(keyFile, []byte(testAPIKey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fakeDT{now: now, projects: map[string]*project{}, parents: map[string]string{}, keyFile: keyFile}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv, keyFile
}

func (f *fakeDT) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-Api-Key") != testAPIKey {
		http.Error(w, "The API key could not be validated", http.StatusUnauthorized)
		return
	}
	if f.fail > 0 {
		f.fail--
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/project/lookup":
		p, ok := f.projects[r.URL.Query().Get("name")+":"+r.URL.Query().Get("version")]
		if !ok {
			http.Error(w, "The project could not be found.", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, p)
	case r.Method == http.MethodPut && r.URL.Path == "/api/v1/project":
		var req struct {
			Name, Version, CollectionLogic string
			Parent                         *struct{ UUID string }
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		parent := ""
		if req.Parent != nil {
			parent = req.Parent.UUID
		}
		p := f.addLocked(req.Name, req.Version, parent)
		p.CollectionLogic = req.CollectionLogic
		writeJSON(w, http.StatusCreated, p)
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/v1/project/"):
		p := f.byUUIDLocked(strings.TrimPrefix(r.URL.Path, "/api/v1/project/"))
		if p == nil {
			http.Error(w, "The project could not be found.", http.StatusNotFound)
			return
		}
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if v, ok := req["isLatest"].(bool); ok {
			p.IsLatest = v
		}
		if v, ok := req["collectionLogic"].(string); ok {
			p.CollectionLogic = v
		}
		writeJSON(w, http.StatusOK, p)
	case r.Method == http.MethodPut && r.URL.Path == "/api/v1/bom":
		var req struct {
			ProjectName, ProjectVersion, ParentUUID, BOM string
			AutoCreate, IsLatest                         bool
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		bom, err := base64.StdEncoding.DecodeString(req.BOM)
		if err != nil || !json.Valid(bom) || !req.AutoCreate {
			http.Error(w, "bad BOM upload", http.StatusBadRequest)
			return
		}
		key := req.ProjectName + ":" + req.ProjectVersion
		p, ok := f.projects[key]
		if !ok {
			p = f.addLocked(req.ProjectName, req.ProjectVersion, req.ParentUUID)
		}
		if req.IsLatest {
			for _, other := range f.projects {
				if other.Name == p.Name {
					other.IsLatest = false
				}
			}
			p.IsLatest = true
		}
		p.LastBOMImport = epochMillis(f.now().UnixMilli())
		f.uploads = append(f.uploads, key)
		writeJSON(w, http.StatusOK, map[string]string{"token": fmt.Sprintf("token-%d", len(f.uploads))})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeDT) addLocked(name, version, parentUUID string) *project {
	f.nextID++
	p := &project{UUID: fmt.Sprintf("uuid-%d", f.nextID), Name: name, Version: version}
	f.projects[name+":"+version] = p
	f.parents[p.UUID] = parentUUID
	return p
}

func (f *fakeDT) byUUIDLocked(uuid string) *project {
	for _, p := range f.projects {
		if p.UUID == uuid {
			return p
		}
	}
	return nil
}

// project returns a copy of name:version, and the name of its parent.
func (f *fakeDT) project(name, version string) (project, string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.projects[name+":"+version]
	if !ok {
		return project{}, "", false
	}
	parent := ""
	if pp := f.byUUIDLocked(f.parents[p.UUID]); pp != nil {
		parent = pp.Name
	}
	return *p, parent, true
}

// failNext makes the next n requests fail with 503.
func (f *fakeDT) failNext(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = n
}

// patchForTest sets isLatest of the project with uuid, as another upload would.
func (f *fakeDT) patchForTest(uuid string, isLatest bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.byUUIDLocked(uuid)
	if p == nil {
		return fmt.Errorf("no project %s", uuid)
	}
	p.IsLatest = isLatest
	return nil
}

func (f *fakeDT) takeUploads() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.uploads
	f.uploads = nil
	return u
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
