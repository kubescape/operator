package nodeagentautoscaler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/kubescape/operator/config"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func coverageNode(name, group string, ready bool) *corev1.Node {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"node.kubernetes.io/instance-type": group}}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: status}}, Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("16Gi")}}}
}

func coverageAutoscaler(t *testing.T, objects ...runtime.Object) (*Autoscaler, *fake.Clientset) {
	t.Helper()
	client := fake.NewClientset(objects...)
	templatePath := filepath.Join(t.TempDir(), "daemonset-template.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(reconcileTestTemplate), 0600))
	cfg := config.NodeAgentAutoscalerConfig{NodeGroupLabel: "node.kubernetes.io/instance-type", DefaultNodeGroup: "default", GoMemLimitPercentage: 0.8, ReconcileInterval: time.Hour, TemplatePath: templatePath, ResourcePercentages: config.NodeAgentAutoscalerResourcePercentages{RequestCPU: 2, RequestMemory: 2, LimitCPU: 5, LimitMemory: 5}, MinResources: config.NodeAgentAutoscalerResourceBounds{CPU: "100m", Memory: "180Mi"}, MaxResources: config.NodeAgentAutoscalerResourceBounds{CPU: "2000m", Memory: "4Gi"}}
	renderer, err := NewTemplateRenderer(templatePath, cfg.GoMemLimitPercentage, cfg.NodeGroupLabel, "")
	require.NoError(t, err)
	return &Autoscaler{client: client, config: cfg, namespace: "kubescape", nodeGrouper: NewNodeGrouper(client, cfg, "kubescape"), templateRenderer: renderer, stopCh: make(chan struct{})}, client
}

func TestReconcileRetainsNotReadyGroupUntilLastNodeIsDeleted(t *testing.T) {
	ctx := context.Background()
	node := coverageNode("node", "m5.large", true)
	a, client := coverageAutoscaler(t, node)
	require.NoError(t, a.Reconcile(ctx))
	original, err := client.AppsV1().DaemonSets("kubescape").Get(ctx, "node-agent-m5-large", metav1.GetOptions{})
	require.NoError(t, err)
	node.Status.Conditions[0].Status = corev1.ConditionFalse
	node.Status.Allocatable = nil
	_, err = client.CoreV1().Nodes().UpdateStatus(ctx, node, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.NoError(t, a.Reconcile(ctx))
	retained, err := client.AppsV1().DaemonSets("kubescape").Get(ctx, original.Name, metav1.GetOptions{})
	require.NoError(t, err, "temporary NotReady must not remove coverage")
	require.Equal(t, original.Spec, retained.Spec, "no resizing from unavailable allocatable")
	require.NoError(t, client.CoreV1().Nodes().Delete(ctx, node.Name, metav1.DeleteOptions{}))
	require.NoError(t, a.Reconcile(ctx))
	list, err := client.AppsV1().DaemonSets("kubescape").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Empty(t, list.Items, "true orphans still removed")
}

func TestNodeEventsCreateAndDeleteWithoutWaitingForPeriodicSweep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, client := coverageAutoscaler(t)
	done := make(chan struct{})
	go func() { defer close(done); a.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Start did not drain")
		}
	})
	require.Eventually(t, func() bool {
		for _, action := range client.Actions() {
			if action.GetVerb() == "watch" && action.GetResource().Resource == "nodes" {
				return true
			}
		}
		return false
	}, 3*time.Second, 10*time.Millisecond, "node watch must be active")
	node := coverageNode("new-node", "m6i.8xlarge", false)
	_, err := client.CoreV1().Nodes().Create(ctx, node, metav1.CreateOptions{})
	require.NoError(t, err)
	// Becoming ready must also trigger promptly; creation alone cannot provision
	// a group whose allocatable resources are not yet usable.
	node.Status.Conditions[0].Status = corev1.ConditionTrue
	_, err = client.CoreV1().Nodes().UpdateStatus(ctx, node, metav1.UpdateOptions{})
	require.NoError(t, err)
	name := "node-agent-m6i-8xlarge"
	require.Eventually(t, func() bool {
		_, err := client.AppsV1().DaemonSets("kubescape").Get(ctx, name, metav1.GetOptions{})
		return err == nil
	}, 4*time.Second, 10*time.Millisecond, "hourly recovery interval must not delay node events")
	require.NoError(t, client.CoreV1().Nodes().Delete(ctx, node.Name, metav1.DeleteOptions{}))
	require.Eventually(t, func() bool {
		list, err := client.AppsV1().DaemonSets("kubescape").List(ctx, metav1.ListOptions{})
		return err == nil && len(list.Items) == 0
	}, 4*time.Second, 10*time.Millisecond, "node delete must clean actual orphans")
}

func TestReconcileDoesNotCreateUnreadyGroup(t *testing.T) {
	node := coverageNode("pending", "m5.large", false)
	node.Status.Allocatable = nil
	a, client := coverageAutoscaler(t, node)
	require.NoError(t, a.Reconcile(context.Background()))
	list, err := client.AppsV1().DaemonSets("kubescape").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Empty(t, list.Items)
}

func TestNodeChangedIgnoresHeartbeatAndDetectsRelevantUpdates(t *testing.T) {
	a, _ := coverageAutoscaler(t)
	a.config.BottlerocketAutoDetect = true
	original := coverageNode("node", "m5.large", true)
	cases := []struct {
		name   string
		change func(*corev1.Node)
		want   bool
	}{
		{"heartbeat", func(n *corev1.Node) { n.Status.Conditions[0].LastHeartbeatTime = metav1.Now() }, false},
		{"unrelated label", func(n *corev1.Node) { n.Labels["unrelated"] = "value" }, false},
		{"readiness", func(n *corev1.Node) { n.Status.Conditions[0].Status = corev1.ConditionFalse }, true},
		{"group label", func(n *corev1.Node) { n.Labels[a.config.NodeGroupLabel] = "m6i.large" }, true},
		{"missing group label", func(n *corev1.Node) { delete(n.Labels, a.config.NodeGroupLabel) }, true},
		{"cpu", func(n *corev1.Node) { n.Status.Allocatable[corev1.ResourceCPU] = resource.MustParse("8") }, true},
		{"memory", func(n *corev1.Node) { n.Status.Allocatable[corev1.ResourceMemory] = resource.MustParse("32Gi") }, true},
		{"bottlerocket", func(n *corev1.Node) { n.Status.NodeInfo.OSImage = "Bottlerocket OS" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			updated := original.DeepCopy()
			tc.change(updated)
			require.Equal(t, tc.want, a.nodeChanged(original, updated))
		})
	}
}

func TestReconcileInventoryFailureDoesNotDeleteManagedDaemonSets(t *testing.T) {
	ctx := context.Background()
	a, client := coverageAutoscaler(t, coverageNode("node", "m5.large", true))
	require.NoError(t, a.Reconcile(ctx))
	client.PrependReactor("list", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("inventory unavailable")
	})
	require.ErrorContains(t, a.Reconcile(ctx), "inventory unavailable")
	_, err := client.AppsV1().DaemonSets("kubescape").Get(ctx, "node-agent-m5-large", metav1.GetOptions{})
	require.NoError(t, err)
}

func TestNodeEventReconciliationRetriesTransientWriteFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, client := coverageAutoscaler(t)
	var attempts atomic.Int32
	client.PrependReactor("create", "daemonsets", func(ktesting.Action) (bool, runtime.Object, error) {
		if attempts.Add(1) == 1 {
			return true, nil, apierrors.NewServiceUnavailable("temporary write failure")
		}
		return false, nil, nil
	})
	done := make(chan struct{})
	go func() { defer close(done); a.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Start did not drain")
		}
	})
	require.Eventually(t, func() bool {
		for _, action := range client.Actions() {
			if action.GetVerb() == "watch" && action.GetResource().Resource == "nodes" {
				return true
			}
		}
		return false
	}, 3*time.Second, 10*time.Millisecond)
	_, err := client.CoreV1().Nodes().Create(ctx, coverageNode("node", "m5.large", true), metav1.CreateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		_, err := client.AppsV1().DaemonSets("kubescape").Get(ctx, "node-agent-m5-large", metav1.GetOptions{})
		return err == nil
	}, 5*time.Second, 10*time.Millisecond, "transient create failure must retry without another node event")
	require.GreaterOrEqual(t, attempts.Load(), int32(2))
}

func TestPeriodicRecoveryAndIdempotentStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, client := coverageAutoscaler(t, coverageNode("node", "m5.large", true))
	a.config.ReconcileInterval = 100 * time.Millisecond
	done := make(chan struct{})
	go func() { defer close(done); a.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Start did not drain")
		}
	})
	name := "node-agent-m5-large"
	require.Eventually(t, func() bool {
		_, err := client.AppsV1().DaemonSets("kubescape").Get(ctx, name, metav1.GetOptions{})
		return err == nil
	}, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, client.AppsV1().DaemonSets("kubescape").Delete(ctx, name, metav1.DeleteOptions{}))
	require.Eventually(t, func() bool {
		_, err := client.AppsV1().DaemonSets("kubescape").Get(ctx, name, metav1.GetOptions{})
		return err == nil
	}, 3*time.Second, 10*time.Millisecond, "periodic recovery must repair deletion without a node event")
	a.Stop()
	a.Stop()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not cancel queue and informer")
	}
}

func TestNotReadyMembersPreserveCollisionNamesAndReadySizing(t *testing.T) {
	ctx := context.Background()
	first := coverageNode("first", "m5.large", true)
	second := coverageNode("second", "m5_large", true)
	a, client := coverageAutoscaler(t, first, second)
	require.NoError(t, a.Reconcile(ctx))
	before, err := client.AppsV1().DaemonSets("kubescape").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, before.Items, 2)
	second.Status.Conditions[0].Status = corev1.ConditionUnknown
	second.Status.Allocatable = nil
	_, err = client.CoreV1().Nodes().UpdateStatus(ctx, second, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.NoError(t, a.Reconcile(ctx))
	for _, ds := range before.Items {
		_, err = client.AppsV1().DaemonSets("kubescape").Get(ctx, ds.Name, metav1.GetOptions{})
		require.NoError(t, err, "NotReady must not rename a colliding group")
	}
	// The unlabeled fallback also keeps presence separate from ready-node sizing.
	delete(first.Labels, a.config.NodeGroupLabel)
	delete(second.Labels, a.config.NodeGroupLabel)
	_, err = client.CoreV1().Nodes().Update(ctx, first, metav1.UpdateOptions{})
	require.NoError(t, err)
	_, err = client.CoreV1().Nodes().Update(ctx, second, metav1.UpdateOptions{})
	require.NoError(t, err)
	groups, err := a.nodeGrouper.getNodeGroups(ctx, true)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.True(t, groups[0].IsDefault)
	require.Equal(t, 2, groups[0].NodeCount)
	require.Equal(t, 1, groups[0].ReadyNodeCount)
	require.Equal(t, first.Status.Allocatable.Cpu().MilliValue(), groups[0].AllocatableCPU.MilliValue())
	require.NoError(t, a.Reconcile(ctx))
	first.Status.Conditions[0].Status = corev1.ConditionFalse
	_, err = client.CoreV1().Nodes().UpdateStatus(ctx, first, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.NoError(t, a.Reconcile(ctx))
	_, err = client.AppsV1().DaemonSets("kubescape").Get(ctx, "node-agent-default", metav1.GetOptions{})
	require.NoError(t, err, "fallback group coverage must survive NotReady")
}

func TestReconcileCreatesNewGroupsBeforeUpdatingExistingOnes(t *testing.T) {
	ctx := context.Background()
	a, client := coverageAutoscaler(t, coverageNode("existing", "m5.large", true))
	require.NoError(t, a.Reconcile(ctx))
	client.ClearActions()
	_, err := client.CoreV1().Nodes().Create(ctx, coverageNode("new", "m6i.large", true), metav1.CreateOptions{})
	require.NoError(t, err)
	require.NoError(t, a.Reconcile(ctx))
	for _, action := range client.Actions() {
		if action.GetResource().Resource == "daemonsets" && (action.GetVerb() == "create" || action.GetVerb() == "update") {
			require.Equal(t, "create", action.GetVerb(), "new coverage must be provisioned before existing groups consume API writes")
			return
		}
	}
	t.Fatal("no DaemonSet writes")
}

func TestReconcileFailedReplacementDoesNotDeleteOldCoverage(t *testing.T) {
	ctx := context.Background()
	a, client := coverageAutoscaler(t, coverageNode("existing", "m5.large", true))
	require.NoError(t, a.Reconcile(ctx))
	// Adding a colliding type changes canonical names and needs replacement DSs.
	_, err := client.CoreV1().Nodes().Create(ctx, coverageNode("new", "m5_large", true), metav1.CreateOptions{})
	require.NoError(t, err)
	client.PrependReactor("create", "daemonsets", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewServiceUnavailable("temporary write failure")
	})
	require.Error(t, a.Reconcile(ctx))
	_, err = client.AppsV1().DaemonSets("kubescape").Get(ctx, "node-agent-m5-large", metav1.GetOptions{})
	require.NoError(t, err, "do not delete old coverage until replacements exist")
}

func TestNotReadyGroupSurvivesCollisionMembershipChanges(t *testing.T) {
	for _, addCollision := range []bool{true, false} {
		t.Run(fmt.Sprintf("addCollision=%t", addCollision), func(t *testing.T) {
			ctx := context.Background()
			survivor := coverageNode("survivor", "m5.large", true)
			other := coverageNode("other", "m5_large", true)
			nodes := []runtime.Object{survivor}
			if !addCollision {
				nodes = append(nodes, other)
			}
			a, client := coverageAutoscaler(t, nodes...)
			require.NoError(t, a.Reconcile(ctx))
			list, err := client.AppsV1().DaemonSets("kubescape").List(ctx, metav1.ListOptions{})
			require.NoError(t, err)
			var originalName string
			for _, ds := range list.Items {
				if ds.Labels[NodeGroupLabelKey] == "m5.large" {
					originalName = ds.Name
				}
			}
			require.NotEmpty(t, originalName)
			survivor.Status.Conditions[0].Status = corev1.ConditionFalse
			_, err = client.CoreV1().Nodes().UpdateStatus(ctx, survivor, metav1.UpdateOptions{})
			require.NoError(t, err)
			if addCollision {
				_, err = client.CoreV1().Nodes().Create(ctx, other, metav1.CreateOptions{})
			} else {
				err = client.CoreV1().Nodes().Delete(ctx, other.Name, metav1.DeleteOptions{})
			}
			require.NoError(t, err)
			require.NoError(t, a.Reconcile(ctx))
			_, err = client.AppsV1().DaemonSets("kubescape").Get(ctx, originalName, metav1.GetOptions{})
			require.NoError(t, err, "zero-ready group must retain its existing DS across canonical name changes")
		})
	}
}

func TestNotReadyDefaultAndRealGroupsRemainDistinctAcrossRenaming(t *testing.T) {
	for _, survivorDefault := range []bool{true, false} {
		for _, addCollision := range []bool{true, false} {
			t.Run(fmt.Sprintf("default=%t/addCollision=%t", survivorDefault, addCollision), func(t *testing.T) {
				ctx := context.Background()
				survivor := coverageNode("survivor", "default", true)
				other := coverageNode("other", "default", true)
				if survivorDefault {
					delete(survivor.Labels, "node.kubernetes.io/instance-type")
				} else {
					delete(other.Labels, "node.kubernetes.io/instance-type")
				}
				objects := []runtime.Object{survivor}
				if !addCollision {
					objects = append(objects, other)
				}
				a, client := coverageAutoscaler(t, objects...)
				require.NoError(t, a.Reconcile(ctx))
				before, err := client.AppsV1().DaemonSets("kubescape").List(ctx, metav1.ListOptions{})
				require.NoError(t, err)
				var originalName string
				for _, ds := range before.Items {
					_, hasLabelSelector := ds.Spec.Template.Spec.NodeSelector[a.config.NodeGroupLabel]
					if hasLabelSelector != survivorDefault {
						originalName = ds.Name
					}
				}
				require.NotEmpty(t, originalName)
				survivor.Status.Conditions[0].Status = corev1.ConditionFalse
				_, err = client.CoreV1().Nodes().UpdateStatus(ctx, survivor, metav1.UpdateOptions{})
				require.NoError(t, err)
				if addCollision {
					_, err = client.CoreV1().Nodes().Create(ctx, other, metav1.CreateOptions{})
				} else {
					err = client.CoreV1().Nodes().Delete(ctx, other.Name, metav1.DeleteOptions{})
				}
				require.NoError(t, err)
				require.NoError(t, a.Reconcile(ctx))
				_, err = client.AppsV1().DaemonSets("kubescape").Get(ctx, originalName, metav1.GetOptions{})
				require.NoError(t, err)
				if !addCollision {
					remaining, err := client.AppsV1().DaemonSets("kubescape").List(ctx, metav1.ListOptions{})
					require.NoError(t, err)
					require.Len(t, remaining.Items, 1, "departed group must not be retained merely for sharing a label value")
				}
				survivor.Status.Conditions[0].Status = corev1.ConditionTrue
				_, err = client.CoreV1().Nodes().UpdateStatus(ctx, survivor, metav1.UpdateOptions{})
				require.NoError(t, err)
				require.NoError(t, a.Reconcile(ctx))
				remaining, err := client.AppsV1().DaemonSets("kubescape").List(ctx, metav1.ListOptions{})
				require.NoError(t, err)
				expected := 1
				if addCollision {
					expected = 2
				}
				require.Len(t, remaining.Items, expected, "ready replacement must retire stale names")
			})
		}
	}
}

func TestRetainedHistoricalNameCanBeReusedBySurvivingGroup(t *testing.T) {
	for _, survivorReady := range []bool{true, false} {
		t.Run(fmt.Sprintf("ready=%t", survivorReady), func(t *testing.T) {
			ctx := context.Background()
			departed := coverageNode("departed", "m5.large", true)
			survivor := coverageNode("survivor", "m5_large", true)
			a, client := coverageAutoscaler(t, departed)
			var invalidUpdates atomic.Int32
			client.PrependReactor("update", "daemonsets", func(action ktesting.Action) (bool, runtime.Object, error) {
				desired := action.(ktesting.UpdateAction).GetObject().(*appsv1.DaemonSet)
				current, err := client.Tracker().Get(appsv1.SchemeGroupVersion.WithResource("daemonsets"), "kubescape", desired.Name)
				if err != nil {
					return true, nil, err
				}
				if !reflect.DeepEqual(current.(*appsv1.DaemonSet).Spec.Selector, desired.Spec.Selector) {
					invalidUpdates.Add(1)
					return true, nil, apierrors.NewBadRequest("spec.selector is immutable")
				}
				return false, nil, nil
			})
			require.NoError(t, a.Reconcile(ctx))
			departed.Status.Conditions[0].Status = corev1.ConditionFalse
			_, err := client.CoreV1().Nodes().UpdateStatus(ctx, departed, metav1.UpdateOptions{})
			require.NoError(t, err)
			_, err = client.CoreV1().Nodes().Create(ctx, survivor, metav1.CreateOptions{})
			require.NoError(t, err)
			require.NoError(t, a.Reconcile(ctx))
			before, err := client.AppsV1().DaemonSets("kubescape").List(ctx, metav1.ListOptions{})
			require.NoError(t, err)
			var survivorAlias string
			for _, ds := range before.Items {
				if ds.Labels[NodeGroupLabelKey] == "m5_large" {
					survivorAlias = ds.Name
				}
			}
			require.NotEmpty(t, survivorAlias)
			require.NoError(t, client.CoreV1().Nodes().Delete(ctx, departed.Name, metav1.DeleteOptions{}))
			if !survivorReady {
				survivor.Status.Conditions[0].Status = corev1.ConditionFalse
				_, err = client.CoreV1().Nodes().UpdateStatus(ctx, survivor, metav1.UpdateOptions{})
				require.NoError(t, err)
			}
			err = a.Reconcile(ctx)
			if survivorReady {
				require.ErrorContains(t, err, "released DaemonSet name")
			} else {
				require.NoError(t, err)
			}
			_, err = client.AppsV1().DaemonSets("kubescape").Get(ctx, survivorAlias, metav1.GetOptions{})
			require.NoError(t, err, "survivor coverage must remain until canonical replacement exists")
			_, err = client.AppsV1().DaemonSets("kubescape").Get(ctx, "node-agent-m5-large", metav1.GetOptions{})
			require.True(t, apierrors.IsNotFound(err), "departed occupant must not be protected by canonical name alone")
			survivor.Status.Conditions[0].Status = corev1.ConditionTrue
			_, err = client.CoreV1().Nodes().UpdateStatus(ctx, survivor, metav1.UpdateOptions{})
			require.NoError(t, err)
			require.NoError(t, a.Reconcile(ctx))
			after, err := client.AppsV1().DaemonSets("kubescape").List(ctx, metav1.ListOptions{})
			require.NoError(t, err)
			require.Len(t, after.Items, 1)
			require.Equal(t, "node-agent-m5-large", after.Items[0].Name)
			require.Equal(t, "m5_large", after.Items[0].Spec.Selector.MatchLabels[NodeGroupLabelKey])
			require.Zero(t, invalidUpdates.Load(), "never update a DaemonSet to a different immutable group selector")
		})
	}
}

func TestHistoricalAliasReleasedOnlyAfterOwnerReplacement(t *testing.T) {
	for _, ownerReady := range []bool{false, true} {
		for _, failReplacement := range []bool{false, true} {
			t.Run(fmt.Sprintf("ownerReady=%t/failReplacement=%t", ownerReady, failReplacement), func(t *testing.T) {
				ctx := context.Background()
				owner := coverageNode("owner", "m5.large", true)
				other := coverageNode("other", "m5_large", true)
				a, client := coverageAutoscaler(t, owner, other)
				require.NoError(t, a.Reconcile(ctx))
				owner.Status.Conditions[0].Status = corev1.ConditionFalse
				_, err := client.CoreV1().Nodes().UpdateStatus(ctx, owner, metav1.UpdateOptions{})
				require.NoError(t, err)
				require.NoError(t, client.CoreV1().Nodes().Delete(ctx, other.Name, metav1.DeleteOptions{}))
				require.NoError(t, a.Reconcile(ctx))
				alias := "node-agent-m5-large-baa340"
				_, err = client.AppsV1().DaemonSets("kubescape").Get(ctx, alias, metav1.GetOptions{})
				require.NoError(t, err)
				_, err = client.CoreV1().Nodes().Create(ctx, coverageNode("new", "m5-large-baa340", true), metav1.CreateOptions{})
				require.NoError(t, err)
				if ownerReady {
					owner.Status.Conditions[0].Status = corev1.ConditionTrue
					_, err = client.CoreV1().Nodes().UpdateStatus(ctx, owner, metav1.UpdateOptions{})
					require.NoError(t, err)
				}
				client.PrependReactor("create", "daemonsets", func(action ktesting.Action) (bool, runtime.Object, error) {
					if failReplacement && action.(ktesting.CreateAction).GetObject().(*appsv1.DaemonSet).Name == "node-agent-m5-large" {
						return true, nil, apierrors.NewServiceUnavailable("replacement unavailable")
					}
					return false, nil, nil
				})
				require.Error(t, a.Reconcile(ctx), "retry after conflict or name release")
				retained, err := client.AppsV1().DaemonSets("kubescape").Get(ctx, alias, metav1.GetOptions{})
				if !ownerReady || failReplacement {
					require.NoError(t, err, "retain alias without a successfully provisioned replacement")
					require.Equal(t, "m5.large", retained.Labels[NodeGroupLabelKey])
				} else {
					require.True(t, apierrors.IsNotFound(err), "release alias after owner replacement succeeds")
					require.NoError(t, a.Reconcile(ctx))
					list, err := client.AppsV1().DaemonSets("kubescape").List(ctx, metav1.ListOptions{})
					require.NoError(t, err)
					require.Len(t, list.Items, 2)
					newDS, err := client.AppsV1().DaemonSets("kubescape").Get(ctx, alias, metav1.GetOptions{})
					require.NoError(t, err)
					require.Equal(t, "m5-large-baa340", newDS.Labels[NodeGroupLabelKey])
				}
			})
		}
	}
}
