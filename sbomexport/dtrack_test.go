package sbomexport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDTClientLooksUpCreatesAndPatchesProjects(t *testing.T) {
	ctx := context.Background()
	f, srv, keyFile := newFakeDT(t, time.Now)
	c := &dtClient{baseURL: srv.URL, apiKeyFile: keyFile, http: srv.Client()}

	p, err := c.lookup(ctx, "cluster", "current")
	require.NoError(t, err)
	assert.Nil(t, p, "a missing project is not an error")

	root, err := c.createCollection(ctx, "cluster", "current", "", rootLogic)
	require.NoError(t, err)
	ns, err := c.createCollection(ctx, "cluster/apps", "current", root.UUID, parentLogic)
	require.NoError(t, err)
	require.NoError(t, c.patch(ctx, ns.UUID, map[string]any{"collectionLogic": rootLogic}))

	got, parent, ok := f.project("cluster/apps", "current")
	require.True(t, ok)
	assert.Equal(t, "cluster", parent)
	assert.Equal(t, rootLogic, got.CollectionLogic)

	p, err = c.lookup(ctx, "cluster/apps", "current")
	require.NoError(t, err)
	assert.Equal(t, ns.UUID, p.UUID)
}

func TestDTClientCreatesAProjectUnderItsParentAndUploadsItsBOM(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	f, srv, keyFile := newFakeDT(t, func() time.Time { return now })
	c := &dtClient{baseURL: srv.URL, apiKeyFile: keyFile, http: srv.Client()}
	ns, err := c.createCollection(ctx, "cluster/apps", "current", "", parentLogic)
	require.NoError(t, err)

	_, err = c.createProject(ctx, "cluster/apps/redis", "8", ns.UUID)
	require.NoError(t, err)
	require.NoError(t, c.uploadBOM(ctx, "cluster/apps/redis", "8", curlCycloneDX))

	got, parent, ok := f.project("cluster/apps/redis", "8")
	require.True(t, ok)
	assert.Equal(t, "cluster/apps", parent)
	assert.True(t, got.IsLatest)
	assert.Equal(t, now, got.LastBOMImport.Time().UTC())
}

func TestDTClientReadsTheAPIKeyOnEveryRequest(t *testing.T) {
	ctx := context.Background()
	_, srv, keyFile := newFakeDT(t, time.Now)
	c := &dtClient{baseURL: srv.URL, apiKeyFile: keyFile, http: srv.Client()}

	require.NoError(t, os.WriteFile(keyFile, []byte("revoked-key"), 0600))
	_, err := c.lookup(ctx, "cluster", "current")
	require.Error(t, err)
	assert.True(t, isAuthError(err))

	require.NoError(t, os.WriteFile(keyFile, []byte(testAPIKey), 0600))
	_, err = c.lookup(ctx, "cluster", "current")
	assert.NoError(t, err, "the rotated key is used without a restart")

	require.NoError(t, os.WriteFile(keyFile, []byte("  \n"), 0600))
	_, err = c.lookup(ctx, "cluster", "current")
	assert.ErrorContains(t, err, "is empty")
}

func TestDTClientErrorCarriesTheStatusAndTheStartOfTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, strings.Repeat("x", 2*errBody), http.StatusInternalServerError)
	}))
	defer srv.Close()
	keyFile := t.TempDir() + "/api-key"
	require.NoError(t, os.WriteFile(keyFile, []byte(testAPIKey), 0600))
	c := &dtClient{baseURL: srv.URL, apiKeyFile: keyFile, http: srv.Client()}

	err := c.uploadBOM(context.Background(), "cluster/apps/redis", "8", curlCycloneDX)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "PUT /api/v1/bom: HTTP 500: "+strings.Repeat("x", errBody))
	assert.NotContains(t, err.Error(), strings.Repeat("x", errBody+1))
	assert.False(t, isAuthError(err))
}

func TestEpochMillisDecodesNumbersAndRFC3339(t *testing.T) {
	tt := []struct {
		name string
		json string
		want time.Time
	}{
		{"epoch milliseconds", `{"lastBomImport":1762776000123}`, time.UnixMilli(1762776000123)},
		{"RFC 3339", `{"lastBomImport":"2025-11-10T12:00:00.123Z"}`, time.UnixMilli(1762776000123)},
		{"null", `{"lastBomImport":null}`, time.Time{}},
		{"missing", `{}`, time.Time{}},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var p project
			require.NoError(t, json.Unmarshal([]byte(tc.json), &p))
			assert.True(t, tc.want.Equal(p.LastBOMImport.Time()), "got %s", p.LastBOMImport.Time())
		})
	}
}
