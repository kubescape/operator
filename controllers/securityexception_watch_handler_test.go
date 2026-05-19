package controllers

import (
	"context"
	"sync"
	"testing"
	"time"

	securityexceptionv1 "github.com/kubescape/operator/api/kubescape/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type mockRescanDispatcher struct {
	mu       sync.Mutex
	requests []RescanRequest
}

func (m *mockRescanDispatcher) Dispatch(_ context.Context, req RescanRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, req)
	return nil
}

func (m *mockRescanDispatcher) Requests() []RescanRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]RescanRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

func newTestScheme(t *testing.T) *runtime.Scheme {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, securityexceptionv1.AddToScheme(scheme))
	return scheme
}

func waitForKey(t *testing.T, queue *CooldownQueue, timeout time.Duration) string {
	t.Helper()

	select {
	case key := <-queue.ResultChan():
		return key
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for debounced key")
	}
	return ""
}

func TestSecurityExceptionWatchHandlerReconcile(t *testing.T) {
	tests := []struct {
		name             string
		request          reconcile.Request
		objects          []client.Object
		expectNamespaces []string
		expectKinds      ScanKinds
	}{
		{
			name: "namespaced exception targets its namespace",
			request: reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "team-a", Name: "se-a"}},
			objects: []client.Object{
				&securityexceptionv1.SecurityException{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "team-a",
						Name:      "se-a",
					},
					Spec: securityexceptionv1.SecurityExceptionSpec{
						Posture: []securityexceptionv1.PostureException{{ControlID: "C-001", Action: "exclude"}},
					},
				},
			},
			expectNamespaces: []string{"team-a"},
			expectKinds:      ScanKinds{Posture: true, Vulnerability: false},
		},
		{
			name:    "cluster exception without selector targets all namespaces",
			request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "cse-all"}},
			objects: []client.Object{
				&securityexceptionv1.ClusterSecurityException{
					ObjectMeta: metav1.ObjectMeta{Name: "cse-all"},
					Spec: securityexceptionv1.SecurityExceptionSpec{
						Vulnerabilities: []securityexceptionv1.VulnerabilityException{{
							Vulnerability: securityexceptionv1.VulnerabilityReference{ID: "CVE-2026-0001"},
							Status:        "approved",
						}},
					},
				},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-b"}},
			},
			expectNamespaces: []string{"team-a", "team-b"},
			expectKinds:      ScanKinds{Posture: false, Vulnerability: true},
		},
		{
			name:    "cluster exception namespace selector filters namespaces",
			request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "cse-filter"}},
			objects: []client.Object{
				&securityexceptionv1.ClusterSecurityException{
					ObjectMeta: metav1.ObjectMeta{Name: "cse-filter"},
					Spec: securityexceptionv1.SecurityExceptionSpec{
						Match: &securityexceptionv1.SecurityExceptionMatch{
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "alpha"}},
						},
						Posture: []securityexceptionv1.PostureException{{ControlID: "C-002", Action: "exclude"}},
					},
				},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "alpha", Labels: map[string]string{"team": "alpha"}}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "beta", Labels: map[string]string{"team": "beta"}}},
			},
			expectNamespaces: []string{"alpha"},
			expectKinds:      ScanKinds{Posture: true, Vulnerability: false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scheme := newTestScheme(t)
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.objects...).Build()
			dispatcher := &mockRescanDispatcher{}
			queue := NewCooldownQueueWithParams(10 * time.Millisecond)
			defer queue.Stop()

			h := NewSecurityExceptionWatchHandler(k8sClient, nil, dispatcher, WithCooldownQueue(queue))

			_, err := h.Reconcile(context.Background(), tc.request)
			require.NoError(t, err)

			key := waitForKey(t, queue, 200*time.Millisecond)
			h.handleKey(context.Background(), key)

			requests := dispatcher.Requests()
			require.Len(t, requests, 1)
			assert.ElementsMatch(t, tc.expectNamespaces, requests[0].Namespaces)
			assert.Equal(t, tc.expectKinds, requests[0].ScanKinds)
		})
	}
}

func TestSecurityExceptionWatchHandlerExpiry(t *testing.T) {
	now := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name             string
		objects          []client.Object
		expectNamespaces []string
		expectKinds      ScanKinds
		expectCalls      int
	}{
		{
			name: "expired cluster exception triggers rescan once",
			objects: []client.Object{
				&securityexceptionv1.ClusterSecurityException{
					ObjectMeta: metav1.ObjectMeta{Name: "cse-expired"},
					Spec: securityexceptionv1.SecurityExceptionSpec{
						ExpiresAt: &metav1.Time{Time: now.Add(-1 * time.Hour)},
						Vulnerabilities: []securityexceptionv1.VulnerabilityException{{
							Vulnerability: securityexceptionv1.VulnerabilityReference{ID: "CVE-2026-0002"},
							Status:        "approved",
						}},
					},
				},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-b"}},
			},
			expectNamespaces: []string{"team-a", "team-b"},
			expectKinds:      ScanKinds{Posture: false, Vulnerability: true},
			expectCalls:      1,
		},
		{
			name: "non-expired exception does not trigger rescan",
			objects: []client.Object{
				&securityexceptionv1.SecurityException{
					ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "se-future"},
					Spec: securityexceptionv1.SecurityExceptionSpec{
						ExpiresAt: &metav1.Time{Time: now.Add(1 * time.Hour)},
						Posture:   []securityexceptionv1.PostureException{{ControlID: "C-003", Action: "exclude"}},
					},
				},
			},
			expectCalls: 0,
		},
		{
			name: "missing expiresAt does not trigger rescan",
			objects: []client.Object{
				&securityexceptionv1.SecurityException{
					ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "se-no-expiry"},
					Spec: securityexceptionv1.SecurityExceptionSpec{
						Posture: []securityexceptionv1.PostureException{{ControlID: "C-004", Action: "exclude"}},
					},
				},
			},
			expectCalls: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scheme := newTestScheme(t)
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.objects...).Build()
			dispatcher := &mockRescanDispatcher{}
			queue := NewCooldownQueueWithParams(time.Hour)
			defer queue.Stop()

			h := NewSecurityExceptionWatchHandler(k8sClient, nil, dispatcher, WithCooldownQueue(queue), WithClock(func() time.Time {
				return now
			}))

			require.NoError(t, h.checkExpired(context.Background()))
			if tc.expectCalls > 0 {
				require.NoError(t, h.checkExpired(context.Background()))
			}

			requests := dispatcher.Requests()
			assert.Len(t, requests, tc.expectCalls)
			if tc.expectCalls == 0 {
				return
			}

			assert.ElementsMatch(t, tc.expectNamespaces, requests[0].Namespaces)
			assert.Equal(t, tc.expectKinds, requests[0].ScanKinds)
		})
	}
}
