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
// makes: project lookup, get by UUID, create, patch (including a move), BOM
// upload to an existing project, and project properties.
type fakeDT struct {
	mu             sync.Mutex
	now            func() time.Time
	projects       map[string]*project          // uuid → project
	parents        map[string]string            // project uuid → parent uuid
	properties     map[string]map[string]string // project uuid → "group/name" → value
	uploads        []string                     // "name:version" of every BOM upload
	patches        map[string]int               // project uuid → PATCH requests
	nextID         int
	fail           int    // answer the next fail requests with 503
	failProperties int    // answer the next property writes with 503
	onPatch        func() // called before a PATCH is applied, without the lock
	keyFile        string // holds testAPIKey
}

// newFakeDT starts a fakeDT and returns it with an API key file holding
// testAPIKey.
func newFakeDT(t *testing.T, now func() time.Time) (*fakeDT, *httptest.Server, string) {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "api-key")
	if err := os.WriteFile(keyFile, []byte(testAPIKey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fakeDT{now: now, projects: map[string]*project{}, parents: map[string]string{}, properties: map[string]map[string]string{}, patches: map[string]int{}, keyFile: keyFile}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv, keyFile
}

func (f *fakeDT) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPatch {
		f.mu.Lock()
		hook := f.onPatch
		f.onPatch = nil
		f.mu.Unlock()
		if hook != nil {
			hook()
		}
	}
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
	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && path == "/api/v1/project/lookup":
		p := f.byNameLocked(r.URL.Query().Get("name"), r.URL.Query().Get("version"))
		if p == nil {
			http.Error(w, "The project could not be found.", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, p)
	case r.Method == http.MethodPut && path == "/api/v1/project":
		var req struct {
			Name, Version, CollectionLogic string
			Parent                         *struct{ UUID string }
			Tags                           []tag
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		parent := ""
		if req.Parent != nil {
			parent = req.Parent.UUID
		}
		p := f.addLocked(req.Name, req.Version, parent, req.Tags)
		p.CollectionLogic = req.CollectionLogic
		writeJSON(w, http.StatusCreated, p)
	case strings.HasSuffix(path, "/property") && strings.HasPrefix(path, "/api/v1/project/"):
		f.serveProperty(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/project/"), "/property"))
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/project/"):
		p := f.projects[strings.TrimPrefix(path, "/api/v1/project/")]
		if p == nil {
			http.Error(w, "The project could not be found.", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, p)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/v1/project/"):
		uuid := strings.TrimPrefix(path, "/api/v1/project/")
		p := f.projects[uuid]
		if p == nil {
			http.Error(w, "The project could not be found.", http.StatusNotFound)
			return
		}
		var req struct {
			IsLatest        *bool
			CollectionLogic *string
			Name, Version   *string
			Parent          *struct{ UUID string }
			Tags            *[]tag
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.patches[uuid]++
		if req.IsLatest != nil {
			p.IsLatest = *req.IsLatest
		}
		// Like Dependency-Track 4.14, a PATCH without collectionLogic sets it
		// to NONE.
		p.CollectionLogic = "NONE"
		if req.CollectionLogic != nil {
			p.CollectionLogic = *req.CollectionLogic
		}
		if req.Name != nil {
			p.Name = *req.Name
		}
		if req.Version != nil {
			p.Version = *req.Version
		}
		if req.Parent != nil {
			f.parents[uuid] = req.Parent.UUID
			p.Parent = &projectParent{UUID: req.Parent.UUID}
		}
		if req.Tags != nil {
			p.Tags = *req.Tags
		}
		writeJSON(w, http.StatusOK, p)
	case r.Method == http.MethodPut && path == "/api/v1/bom":
		var req struct {
			ProjectName, ProjectVersion, BOM string
			AutoCreate, IsLatest             bool
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		bom, err := base64.StdEncoding.DecodeString(req.BOM)
		if err != nil || !json.Valid(bom) {
			http.Error(w, "bad BOM upload", http.StatusBadRequest)
			return
		}
		p := f.byNameLocked(req.ProjectName, req.ProjectVersion)
		if p == nil {
			http.Error(w, "The project could not be found.", http.StatusNotFound)
			return
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
		f.uploads = append(f.uploads, req.ProjectName+":"+req.ProjectVersion)
		writeJSON(w, http.StatusOK, map[string]string{"token": fmt.Sprintf("token-%d", len(f.uploads))})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeDT) serveProperty(w http.ResponseWriter, r *http.Request, uuid string) {
	if f.projects[uuid] == nil {
		http.Error(w, "The project could not be found.", http.StatusNotFound)
		return
	}
	if r.Method == http.MethodGet {
		var out []projectProperty
		for k, v := range f.properties[uuid] {
			group, name, _ := strings.Cut(k, "/")
			out = append(out, projectProperty{GroupName: group, PropertyName: name, PropertyValue: v, PropertyType: "STRING"})
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	if f.failProperties > 0 {
		f.failProperties--
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	var p projectProperty
	_ = json.NewDecoder(r.Body).Decode(&p)
	key := p.GroupName + "/" + p.PropertyName
	if f.properties[uuid] == nil {
		f.properties[uuid] = map[string]string{}
	}
	_, exists := f.properties[uuid][key]
	switch {
	case r.Method == http.MethodPut && exists:
		http.Error(w, "A property with the specified project/group/name combination already exists.", http.StatusConflict)
	case r.Method == http.MethodPut:
		f.properties[uuid][key] = p.PropertyValue
		writeJSON(w, http.StatusCreated, p)
	case r.Method == http.MethodPost && exists:
		f.properties[uuid][key] = p.PropertyValue
		writeJSON(w, http.StatusOK, p)
	default:
		http.Error(w, "The property could not be found.", http.StatusNotFound)
	}
}

func (f *fakeDT) byNameLocked(name, version string) *project {
	for _, p := range f.projects {
		if p.Name == name && p.Version == version {
			return p
		}
	}
	return nil
}

func (f *fakeDT) addLocked(name, version, parentUUID string, tags []tag) *project {
	f.nextID++
	p := &project{UUID: fmt.Sprintf("00000000-0000-0000-0000-%012d", f.nextID), Name: name, Version: version, Tags: tags}
	if parentUUID != "" {
		p.Parent = &projectParent{UUID: parentUUID}
	}
	f.projects[p.UUID] = p
	f.parents[p.UUID] = parentUUID
	return p
}

// addProject creates a project the way a person would, without the
// exporter's tag, and returns its uuid.
func (f *fakeDT) addProject(name, version, parentUUID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addLocked(name, version, parentUUID, nil).UUID
}

// patchCount returns how many PATCH requests the project with uuid got.
func (f *fakeDT) patchCount(uuid string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.patches[uuid]
}

// project returns a copy of name:version, and the name of its parent.
func (f *fakeDT) project(name, version string) (project, string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.byNameLocked(name, version)
	if p == nil {
		return project{}, "", false
	}
	parent := ""
	if pp := f.projects[f.parents[p.UUID]]; pp != nil {
		parent = pp.Name
	}
	return *p, parent, true
}

// digestOwnerForTest returns the image digest recorded on the project with uuid.
func (f *fakeDT) digestOwnerForTest(uuid string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.projects[uuid] == nil {
		return "", fmt.Errorf("no project %s", uuid)
	}
	return f.properties[uuid][digestPropertyGroup+"/"+digestPropertyName], nil
}

// count returns how many projects exist.
func (f *fakeDT) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.projects)
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
	p := f.projects[uuid]
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
