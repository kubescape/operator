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

// project is the part of a Dependency-Track project the exporter reads.
type project struct {
	UUID            string      `json:"uuid"`
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	IsLatest        bool        `json:"isLatest"`
	CollectionLogic string      `json:"collectionLogic"`
	LastBOMImport   epochMillis `json:"lastBomImport"`
}

// epochMillis is a Dependency-Track timestamp. It decodes from epoch
// milliseconds or from an RFC 3339 string.
type epochMillis int64

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

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("%s %s: read response: %w", method, path, err)
	}

	for _, s := range ok {
		if resp.StatusCode != s {
			continue
		}
		if out != nil && len(data) > 0 && resp.StatusCode < 300 { // a 404 body is plain text
			if err := json.Unmarshal(data, out); err != nil {
				return resp.StatusCode, fmt.Errorf("%s %s: decode response: %w", method, path, err)
			}
		}
		return resp.StatusCode, nil
	}
	msg := strings.TrimSpace(string(data))
	if len(msg) > errBody {
		msg = msg[:errBody]
	}
	return resp.StatusCode, &httpError{method: method, path: path, status: resp.StatusCode, body: msg}
}

// httpError is a response with an unexpected status.
type httpError struct {
	method, path string
	status       int
	body         string
}

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

// createCollection creates the collection project name:version with the given
// collection logic, under parentUUID unless it is empty.
func (c *dtClient) createCollection(ctx context.Context, name, version, parentUUID, logic string) (*project, error) {
	body := map[string]any{"name": name, "version": version, "collectionLogic": logic}
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

// uploadBOM uploads bom as the latest version of name:version, creating the
// project under parentUUID when it does not exist. Dependency-Track processes
// the BOM asynchronously after answering.
func (c *dtClient) uploadBOM(ctx context.Context, name, version, parentUUID string, bom []byte) error {
	body := map[string]any{
		"projectName":    name,
		"projectVersion": version,
		"autoCreate":     true,
		"isLatest":       true,
		"bom":            base64.StdEncoding.EncodeToString(bom),
	}
	if parentUUID != "" {
		body["parentUUID"] = parentUUID
	}
	_, err := c.do(ctx, http.MethodPut, "/api/v1/bom", body, nil, http.StatusOK)
	return err
}
