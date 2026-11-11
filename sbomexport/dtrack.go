package sbomexport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// managedTag marks the projects the exporter created. It changes no other
	// project: no collection logic, no BOM, no move.
	managedTag = "managed-by:kubescape"

	// The project property that records which image digest a project's BOM
	// came from, so two images cannot overwrite each other's project.
	digestPropertyGroup = "kubescape"
	digestPropertyName  = "image-digest"
)

// project is the part of a Dependency-Track project the exporter reads.
type project struct {
	UUID            string      `json:"uuid"`
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	IsLatest        bool        `json:"isLatest"`
	CollectionLogic string      `json:"collectionLogic"`
	LastBOMImport   epochMillis `json:"lastBomImport"`
	Tags            []tag       `json:"tags"`
	// Parent is set in a GET by UUID; a lookup by name leaves it out.
	Parent *projectParent `json:"parent,omitempty"`
}

// projectParent is a project's parent, by UUID.
type projectParent struct {
	UUID string `json:"uuid"`
}

type tag struct {
	Name string `json:"name"`
}

// managed reports whether the exporter created p.
func (p *project) managed() bool {
	for _, t := range p.Tags {
		if strings.EqualFold(t.Name, managedTag) {
			return true
		}
	}
	return false
}

// epochMillis is a Dependency-Track timestamp. It decodes from epoch
// milliseconds or from an RFC 3339 string.
type epochMillis int64

// UnmarshalJSON decodes a number of milliseconds, an RFC 3339 string, or null.
func (m *epochMillis) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*m = 0
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err == nil {
		*m = epochMillis(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("timestamp is neither a number nor a string: %s", b)
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return err
	}
	*m = epochMillis(t.UnixMilli())
	return nil
}

// Time returns the timestamp as a time.Time; zero when Dependency-Track sent none.
func (m epochMillis) Time() time.Time {
	if m == 0 {
		return time.Time{}
	}
	return time.UnixMilli(int64(m))
}

// dtClient calls the Dependency-Track API v1.
type dtClient struct {
	baseURL    string
	apiKeyFile string
	http       *http.Client
}

// errBody is how much of an error response goes into an error message.
const errBody = 300

// do sends one request. The API key is read from apiKeyFile on every call, so
// a rotated Secret takes effect without a restart. A status in ok is a
// success, and a 2xx body is decoded into out when out is not nil; any other
// status is an error.
func (c *dtClient) do(ctx context.Context, method, path string, body any, out any, ok ...int) (int, error) {
	key, err := os.ReadFile(c.apiKeyFile)
	if err != nil {
		return 0, fmt.Errorf("read Dependency-Track API key: %w", err)
	}
	if len(bytes.TrimSpace(key)) == 0 {
		return 0, fmt.Errorf("the Dependency-Track API key file %s is empty", c.apiKeyFile)
	}

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Api-Key", string(bytes.TrimSpace(key)))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// errors name the path without its query, which can hold a project name
	errPath, _, _ := strings.Cut(path, "?")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", method, errPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("%s %s: read response: %w", method, errPath, err)
	}

	for _, s := range ok {
		if resp.StatusCode != s {
			continue
		}
		if out != nil && len(data) > 0 && resp.StatusCode < 300 { // a 404 body is plain text
			if err := json.Unmarshal(data, out); err != nil {
				return resp.StatusCode, fmt.Errorf("%s %s: decode response: %w", method, errPath, err)
			}
		}
		return resp.StatusCode, nil
	}
	msg := strings.TrimSpace(string(data))
	if len(msg) > errBody {
		msg = msg[:errBody]
	}
	return resp.StatusCode, &httpError{method: method, path: errPath, status: resp.StatusCode, body: msg}
}

// httpError is a response with an unexpected status.
type httpError struct {
	method, path string
	status       int
	body         string
}

// Error names the request and quotes the start of the response body.
func (e *httpError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.method, e.path, e.status, e.body)
}

// isAuthError reports whether err is Dependency-Track refusing the API key or
// one of its permissions.
func isAuthError(err error) bool {
	var h *httpError
	return errors.As(err, &h) && (h.status == http.StatusUnauthorized || h.status == http.StatusForbidden)
}

// lookup returns the project name:version, or nil when it does not exist.
func (c *dtClient) lookup(ctx context.Context, name, version string) (*project, error) {
	q := url.Values{"name": {name}, "version": {version}}
	var p project
	status, err := c.do(ctx, http.MethodGet, "/api/v1/project/lookup?"+q.Encode(), nil, &p, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	return &p, nil
}

// getByUUID returns the project with uuid, or nil when it does not exist.
// Dependency-Track answers 400 for some UUIDs it does not know.
func (c *dtClient) getByUUID(ctx context.Context, uuid string) (*project, error) {
	var p project
	status, err := c.do(ctx, http.MethodGet, "/api/v1/project/"+url.PathEscape(uuid), nil, &p, http.StatusOK, http.StatusNotFound, http.StatusBadRequest)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, nil
	}
	return &p, nil
}

// find returns the project ref points at, or nil when it does not exist.
func (c *dtClient) find(ctx context.Context, ref projectRef) (*project, error) {
	if ref.uuid != "" {
		return c.getByUUID(ctx, ref.uuid)
	}
	return c.lookup(ctx, ref.name, ref.version)
}

// createCollection creates the collection project name:version with the given
// collection logic, under parentUUID unless it is empty, tagged as created by
// the exporter.
func (c *dtClient) createCollection(ctx context.Context, name, version, parentUUID, logic string) (*project, error) {
	body := map[string]any{"name": name, "version": version, "collectionLogic": logic, "tags": []tag{{Name: managedTag}}}
	if parentUUID != "" {
		body["parent"] = map[string]string{"uuid": parentUUID}
	}
	var p project
	if _, err := c.do(ctx, http.MethodPut, "/api/v1/project", body, &p, http.StatusCreated, http.StatusOK); err != nil {
		return nil, err
	}
	return &p, nil
}

// patch changes the given fields of the project with uuid. Dependency-Track
// answers 304 when nothing changed.
func (c *dtClient) patch(ctx context.Context, uuid string, fields map[string]any) error {
	_, err := c.do(ctx, http.MethodPatch, "/api/v1/project/"+url.PathEscape(uuid), fields, nil, http.StatusOK, http.StatusNotModified)
	return err
}

// createProject creates the project name:version under parentUUID, tagged as
// created by the exporter.
func (c *dtClient) createProject(ctx context.Context, name, version, parentUUID string) (*project, error) {
	body := map[string]any{"name": name, "version": version, "tags": []tag{{Name: managedTag}}}
	if parentUUID != "" {
		body["parent"] = map[string]string{"uuid": parentUUID}
	}
	var p project
	if _, err := c.do(ctx, http.MethodPut, "/api/v1/project", body, &p, http.StatusCreated, http.StatusOK); err != nil {
		return nil, err
	}
	return &p, nil
}

// uploadBOM uploads bom as the latest version of the existing project
// name:version. Dependency-Track processes the BOM asynchronously after
// answering.
func (c *dtClient) uploadBOM(ctx context.Context, name, version string, bom []byte) error {
	body := map[string]any{
		"projectName":    name,
		"projectVersion": version,
		"autoCreate":     false,
		"isLatest":       true,
		"bom":            base64.StdEncoding.EncodeToString(bom),
	}
	_, err := c.do(ctx, http.MethodPut, "/api/v1/bom", body, nil, http.StatusOK)
	return err
}

// projectProperty is a Dependency-Track project property.
type projectProperty struct {
	GroupName     string `json:"groupName"`
	PropertyName  string `json:"propertyName"`
	PropertyValue string `json:"propertyValue"`
	PropertyType  string `json:"propertyType"`
}

// digestOwner returns the image digest recorded on the project with uuid, or
// "" when none is.
func (c *dtClient) digestOwner(ctx context.Context, uuid string) (string, error) {
	var props []projectProperty
	if _, err := c.do(ctx, http.MethodGet, "/api/v1/project/"+url.PathEscape(uuid)+"/property", nil, &props, http.StatusOK); err != nil {
		return "", err
	}
	for _, p := range props {
		if p.GroupName == digestPropertyGroup && p.PropertyName == digestPropertyName {
			return p.PropertyValue, nil
		}
	}
	return "", nil
}

// setDigestOwner records digest on the project with uuid: PUT creates the
// property, and answers 409 when it exists, which POST then updates.
func (c *dtClient) setDigestOwner(ctx context.Context, uuid, digest string) error {
	body := projectProperty{GroupName: digestPropertyGroup, PropertyName: digestPropertyName, PropertyValue: digest, PropertyType: "STRING"}
	path := "/api/v1/project/" + url.PathEscape(uuid) + "/property"
	status, err := c.do(ctx, http.MethodPut, path, body, nil, http.StatusCreated, http.StatusOK, http.StatusConflict)
	if err != nil || status != http.StatusConflict {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, path, body, nil, http.StatusOK, http.StatusNotModified)
	return err
}
