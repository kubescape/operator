package controllers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	securityexceptionv1 "github.com/kubescape/operator/api/kubescape/v1"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/panjf2000/ants/v2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const defaultExpiryInterval = 5 * time.Minute

type ScanKinds struct {
	Posture        bool
	Vulnerability  bool
}

type RescanRequest struct {
	Namespaces []string
	ScanKinds  ScanKinds
}

type RescanDispatcher interface {
	Dispatch(ctx context.Context, req RescanRequest) error
}

type DefaultRescanDispatcher struct {
	cfg        config.IConfig
	workerPool *ants.PoolWithFunc
}

func NewRescanDispatcher(cfg config.IConfig, workerPool *ants.PoolWithFunc) *DefaultRescanDispatcher {
	return &DefaultRescanDispatcher{cfg: cfg, workerPool: workerPool}
}

func (d *DefaultRescanDispatcher) Dispatch(ctx context.Context, req RescanRequest) error {
	var errs []error

	for _, ns := range req.Namespaces {
		if d.cfg != nil && d.cfg.SkipNamespace(ns) {
			continue
		}

		if req.ScanKinds.Posture && d.cfg != nil && d.cfg.Components().Kubescape.Enabled {
			if err := d.dispatchPosture(ctx, ns); err != nil {
				errs = append(errs, err)
			}
		}
		if req.ScanKinds.Vulnerability && d.cfg != nil && d.cfg.Components().Kubevuln.Enabled {
			if err := d.dispatchVulnerability(ctx, ns); err != nil {
				errs = append(errs, err)
			}
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

func (d *DefaultRescanDispatcher) dispatchPosture(ctx context.Context, namespace string) error {
	cmd := &apis.Command{
		CommandName: apis.TypeRunKubescape,
		Args: map[string]interface{}{
			utils.KubescapeScanV1: utilsmetav1.PostScanRequest{
				IncludeNamespaces: []string{namespace},
				TargetNames:        []string{"all"},
				TargetType:         utilsapisv1.KindFramework,
				HostScanner:        ptr.To(false),
			},
		},
	}
	return utils.AddCommandToChannel(ctx, d.cfg, cmd, d.workerPool)
}

func (d *DefaultRescanDispatcher) dispatchVulnerability(ctx context.Context, namespace string) error {
	designator := identifiers.PortalDesignator{
		Attributes: map[string]string{
			identifiers.AttributeNamespace: namespace,
		},
	}
	cmd := &apis.Command{
		CommandName: apis.TypeScanImages,
		Designators: []identifiers.PortalDesignator{designator},
	}
	return utils.AddCommandToChannel(ctx, d.cfg, cmd, d.workerPool)
}

type SecurityExceptionWatchHandler struct {
	client         client.Client
	cfg            config.IConfig
	dispatcher     RescanDispatcher
	queue          *CooldownQueue
	expiryInterval time.Duration
	now            func() time.Time

	expiredMu  sync.Mutex
	expiredMap map[string]struct{}
}

type HandlerOption func(*SecurityExceptionWatchHandler)

func WithCooldownQueue(queue *CooldownQueue) HandlerOption {
	return func(h *SecurityExceptionWatchHandler) {
		if queue != nil {
			h.queue = queue
		}
	}
}

func WithExpiryInterval(interval time.Duration) HandlerOption {
	return func(h *SecurityExceptionWatchHandler) {
		if interval > 0 {
			h.expiryInterval = interval
		}
	}
}

func WithClock(now func() time.Time) HandlerOption {
	return func(h *SecurityExceptionWatchHandler) {
		if now != nil {
			h.now = now
		}
	}
}

func NewSecurityExceptionWatchHandler(k8sClient client.Client, cfg config.IConfig, dispatcher RescanDispatcher, opts ...HandlerOption) *SecurityExceptionWatchHandler {
	h := &SecurityExceptionWatchHandler{
		client:         k8sClient,
		cfg:            cfg,
		dispatcher:     dispatcher,
		queue:          NewCooldownQueue(),
		expiryInterval: defaultExpiryInterval,
		now:            time.Now,
		expiredMap:     map[string]struct{}{},
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

func (h *SecurityExceptionWatchHandler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	kind := securityexceptionv1.SecurityExceptionKind
	if req.Namespace == "" {
		kind = securityexceptionv1.ClusterSecurityExceptionKind
	}

	h.queue.Enqueue(makeExceptionKey(kind, req.Namespace, req.Name))
	return ctrl.Result{}, nil
}

func (h *SecurityExceptionWatchHandler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&securityexceptionv1.SecurityException{}).
		Watches(source.Kind(mgr.GetCache(), &securityexceptionv1.ClusterSecurityException{}, &handler.EnqueueRequestForObject{})).
		Complete(h); err != nil {
		return err
	}
	return nil
}

// Start runs the debounce worker and expiry loop.
func (h *SecurityExceptionWatchHandler) Start(ctx context.Context) error {
	go h.runQueue(ctx)
	if h.expiryInterval > 0 {
		go h.runExpiry(ctx)
	}
	<-ctx.Done()
	h.queue.Stop()
	return nil
}

func (h *SecurityExceptionWatchHandler) runQueue(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case key, ok := <-h.queue.ResultChan():
			if !ok {
				return
			}
			h.handleKey(ctx, key)
		}
	}
}

func (h *SecurityExceptionWatchHandler) runExpiry(ctx context.Context) {
	if err := h.checkExpired(ctx); err != nil {
		logger.L().Ctx(ctx).Warning("failed initial expiry check", helpers.Error(err))
	}

	ticker := time.NewTicker(h.expiryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := h.checkExpired(ctx); err != nil {
				logger.L().Ctx(ctx).Warning("expiry check failed", helpers.Error(err))
			}
		}
	}
}

func (h *SecurityExceptionWatchHandler) handleKey(ctx context.Context, key string) {
	kind, namespace, name, err := parseExceptionKey(key)
	if err != nil {
		logger.L().Ctx(ctx).Warning("invalid exception key", helpers.String("key", key), helpers.Error(err))
		return
	}

	spec, exists, err := h.fetchSpec(ctx, kind, namespace, name)
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to fetch exception", helpers.String("key", key), helpers.Error(err))
		return
	}

	req := RescanRequest{
		ScanKinds: scanKindsForSpec(spec, exists),
	}

	namespaces, err := h.resolveNamespaces(ctx, kind, namespace, spec, exists)
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to resolve namespaces", helpers.String("key", key), helpers.Error(err))
		return
	}

	if len(namespaces) == 0 || h.dispatcher == nil {
		return
	}

	req.Namespaces = namespaces
	if err := h.dispatcher.Dispatch(ctx, req); err != nil {
		logger.L().Ctx(ctx).Warning("failed to dispatch rescan", helpers.String("key", key), helpers.Error(err))
	}
}

func (h *SecurityExceptionWatchHandler) checkExpired(ctx context.Context) error {
	now := h.now()

	if err := h.checkExpiredSecurityExceptions(ctx, now); err != nil {
		return err
	}
	if err := h.checkExpiredClusterSecurityExceptions(ctx, now); err != nil {
		return err
	}

	return nil
}

func (h *SecurityExceptionWatchHandler) checkExpiredSecurityExceptions(ctx context.Context, now time.Time) error {
	var list securityexceptionv1.SecurityExceptionList
	if err := h.client.List(ctx, &list); err != nil {
		return err
	}

	for i := range list.Items {
		item := list.Items[i]
		if !isExpired(item.Spec.ExpiresAt, now) {
			h.clearExpired(makeExceptionKey(securityexceptionv1.SecurityExceptionKind, item.Namespace, item.Name))
			continue
		}

		key := makeExceptionKey(securityexceptionv1.SecurityExceptionKind, item.Namespace, item.Name)
		if !h.markExpired(key) {
			continue
		}

		if h.dispatcher == nil {
			continue
		}

		namespaces := h.filterNamespaces([]string{item.Namespace})
		if len(namespaces) == 0 {
			continue
		}

		req := RescanRequest{
			Namespaces: namespaces,
			ScanKinds:  scanKindsForSpec(item.Spec, true),
		}
		if err := h.dispatcher.Dispatch(ctx, req); err != nil {
			logger.L().Ctx(ctx).Warning("failed to dispatch expired rescan", helpers.String("key", key), helpers.Error(err))
		}
	}

	return nil
}

func (h *SecurityExceptionWatchHandler) checkExpiredClusterSecurityExceptions(ctx context.Context, now time.Time) error {
	var list securityexceptionv1.ClusterSecurityExceptionList
	if err := h.client.List(ctx, &list); err != nil {
		return err
	}

	for i := range list.Items {
		item := list.Items[i]
		if !isExpired(item.Spec.ExpiresAt, now) {
			h.clearExpired(makeExceptionKey(securityexceptionv1.ClusterSecurityExceptionKind, "", item.Name))
			continue
		}

		key := makeExceptionKey(securityexceptionv1.ClusterSecurityExceptionKind, "", item.Name)
		if !h.markExpired(key) {
			continue
		}

		if h.dispatcher == nil {
			continue
		}

		namespaces, err := h.resolveNamespaces(ctx, securityexceptionv1.ClusterSecurityExceptionKind, "", item.Spec, true)
		if err != nil {
			logger.L().Ctx(ctx).Warning("failed to resolve namespaces", helpers.String("key", key), helpers.Error(err))
			continue
		}
		if len(namespaces) == 0 {
			continue
		}

		req := RescanRequest{
			Namespaces: namespaces,
			ScanKinds:  scanKindsForSpec(item.Spec, true),
		}
		if err := h.dispatcher.Dispatch(ctx, req); err != nil {
			logger.L().Ctx(ctx).Warning("failed to dispatch expired rescan", helpers.String("key", key), helpers.Error(err))
		}
	}

	return nil
}

func (h *SecurityExceptionWatchHandler) fetchSpec(ctx context.Context, kind, namespace, name string) (securityexceptionv1.SecurityExceptionSpec, bool, error) {
	switch kind {
	case securityexceptionv1.SecurityExceptionKind:
		obj := &securityexceptionv1.SecurityException{}
		err := h.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, obj)
		if apierrors.IsNotFound(err) {
			return securityexceptionv1.SecurityExceptionSpec{}, false, nil
		}
		if err != nil {
			return securityexceptionv1.SecurityExceptionSpec{}, false, err
		}
		return obj.Spec, true, nil
	case securityexceptionv1.ClusterSecurityExceptionKind:
		obj := &securityexceptionv1.ClusterSecurityException{}
		err := h.client.Get(ctx, client.ObjectKey{Name: name}, obj)
		if apierrors.IsNotFound(err) {
			return securityexceptionv1.SecurityExceptionSpec{}, false, nil
		}
		if err != nil {
			return securityexceptionv1.SecurityExceptionSpec{}, false, err
		}
		return obj.Spec, true, nil
	default:
		return securityexceptionv1.SecurityExceptionSpec{}, false, fmt.Errorf("unsupported kind: %s", kind)
	}
}

func (h *SecurityExceptionWatchHandler) resolveNamespaces(ctx context.Context, kind, namespace string, spec securityexceptionv1.SecurityExceptionSpec, exists bool) ([]string, error) {
	if kind == securityexceptionv1.SecurityExceptionKind {
		if namespace == "" {
			return nil, fmt.Errorf("missing namespace for SecurityException")
		}
		return h.filterNamespaces([]string{namespace}), nil
	}

	if !exists || spec.Match == nil || spec.Match.NamespaceSelector == nil {
		return h.listNamespaces(ctx, labels.Everything())
	}

	selector, err := metav1.LabelSelectorAsSelector(spec.Match.NamespaceSelector)
	if err != nil {
		return nil, err
	}
	return h.listNamespaces(ctx, selector)
}

func (h *SecurityExceptionWatchHandler) listNamespaces(ctx context.Context, selector labels.Selector) ([]string, error) {
	var list corev1.NamespaceList
	if selector == nil {
		selector = labels.Everything()
	}
	if err := h.client.List(ctx, &list, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, err
	}

	namespaces := make([]string, 0, len(list.Items))
	for i := range list.Items {
		ns := list.Items[i].Name
		if h.cfg != nil && h.cfg.SkipNamespace(ns) {
			continue
		}
		namespaces = append(namespaces, ns)
	}
	return namespaces, nil
}

func (h *SecurityExceptionWatchHandler) filterNamespaces(namespaces []string) []string {
	if h.cfg == nil {
		return namespaces
	}
	filtered := make([]string, 0, len(namespaces))
	for _, ns := range namespaces {
		if h.cfg.SkipNamespace(ns) {
			continue
		}
		filtered = append(filtered, ns)
	}
	return filtered
}

func (h *SecurityExceptionWatchHandler) markExpired(key string) bool {
	h.expiredMu.Lock()
	defer h.expiredMu.Unlock()

	if _, exists := h.expiredMap[key]; exists {
		return false
	}
	if h.expiredMap == nil {
		h.expiredMap = map[string]struct{}{}
	}
	h.expiredMap[key] = struct{}{}
	return true
}

func (h *SecurityExceptionWatchHandler) clearExpired(key string) {
	h.expiredMu.Lock()
	defer h.expiredMu.Unlock()

	delete(h.expiredMap, key)
}

func scanKindsForSpec(spec securityexceptionv1.SecurityExceptionSpec, exists bool) ScanKinds {
	if !exists {
		return ScanKinds{Posture: true, Vulnerability: true}
	}

	kinds := ScanKinds{
		Posture:       len(spec.Posture) > 0,
		Vulnerability: len(spec.Vulnerabilities) > 0,
	}
	if !kinds.Posture && !kinds.Vulnerability {
		kinds.Posture = true
		kinds.Vulnerability = true
	}
	return kinds
}

func isExpired(expiresAt *metav1.Time, now time.Time) bool {
	if expiresAt == nil {
		return false
	}
	return expiresAt.Time.Before(now)
}

func makeExceptionKey(kind, namespace, name string) string {
	return strings.Join([]string{kind, namespace, name}, "/")
}

func parseExceptionKey(key string) (string, string, string, error) {
	parts := strings.SplitN(key, "/", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid key: %s", key)
	}
	return parts[0], parts[1], parts[2], nil
}
