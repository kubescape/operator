package utils

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func authTestServer(t *testing.T, got *string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u.Host
}

func TestInitHttpClient_SendsBearerWhenTokenFilePresent(t *testing.T) {
	var got string
	host := authTestServer(t, &got)
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("abc123\n"), 0o600))
	t.Setenv("KS_API_TOKEN_FILE", tokenFile)

	client := InitHttpClient(host)
	req, err := http.NewRequest(http.MethodGet, "http://"+host+"/x", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, "Bearer abc123", got)
}

func TestInitHttpClient_NoHeaderWithoutFile(t *testing.T) {
	var got string
	host := authTestServer(t, &got)
	t.Setenv("KS_API_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))

	client := InitHttpClient(host)
	req, err := http.NewRequest(http.MethodGet, "http://"+host+"/x", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Empty(t, got)
}

func TestAuthRejected(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		err := AuthRejected(&http.Response{StatusCode: code}, "kubescape")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "kubescape rejected the API token")
		assert.Contains(t, err.Error(), "KS_API_TOKEN_FILE")
	}
	for _, code := range []int{http.StatusOK, http.StatusInternalServerError, http.StatusNotFound} {
		assert.NoError(t, AuthRejected(&http.Response{StatusCode: code}, "kubevuln"))
	}
	assert.NoError(t, AuthRejected(nil, "kubevuln"))
}
