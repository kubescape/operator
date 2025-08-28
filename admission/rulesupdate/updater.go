package rulesupdate

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	OperatorCommandTypeRuntimeUpdateRules = "RuntimeUpdateRules"
)

type RulesUpdater struct {
	k8sClient *k8sinterface.KubernetesApi
	interval  time.Duration
	namespace string
	ctx       context.Context
	cancel    context.CancelFunc
}

type RulesUpdaterConfig struct {
	Interval  time.Duration `mapstructure:"interval"`
	Namespace string        `mapstructure:"namespace"`
	Enabled   bool          `mapstructure:"enabled"`
}

func NewRulesUpdator(ctx context.Context, k8sClient *k8sinterface.KubernetesApi, config RulesUpdaterConfig) *RulesUpdater {
	ctx, cancel := context.WithCancel(ctx)
	updater := &RulesUpdater{
		k8sClient: k8sClient,
		interval:  config.Interval,
		namespace: config.Namespace,
		ctx:       ctx,
		cancel:    cancel,
	}

	return updater
}

func (ru *RulesUpdater) Start() {
	logger.L().Info("rules updater started")
	go func() {
		for {
			select {
			case <-ru.ctx.Done():
				ru.cancel()
				logger.L().Info("rules updater stopped")
				return
			case <-time.After(ru.interval):
				if err := ru.SendUpdateRulesCommand(); err != nil {
					logger.L().Error("error sending update rules command", helpers.Error(err))
				}
			}
		}
	}()
}

func (ru *RulesUpdater) SendUpdateRulesCommand() error {

	logger.L().Info("sending update rules command")
	cmd := &v1alpha1.OperatorCommand{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "kubescape.io/v1alpha1",
			Kind:       "OperatorCommand",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("update-rules-%s", uuid.New().String()[:8]),
			Namespace: ru.namespace,
			Labels: map[string]string{
				"kubescape.io/app-name":  "node-agent",
				"kubescape.io/node-name": "operator",
			},
		},
		Spec: v1alpha1.OperatorCommandSpec{
			GUID:           uuid.New().String(),
			CommandType:    OperatorCommandTypeRuntimeUpdateRules,
			CommandVersion: "v1",
		},
	}

	un, err := runtime.DefaultUnstructuredConverter.ToUnstructured(cmd)
	if err != nil {
		return fmt.Errorf("error converting OperatorCommand to unstructured: %v", err)
	}

	_, err = ru.k8sClient.GetDynamicClient().Resource(v1alpha1.SchemaGroupVersionResource).Namespace(ru.namespace).Create(
		ru.ctx,
		&unstructured.Unstructured{Object: un},
		metav1.CreateOptions{},
	)
	if err != nil {
		return fmt.Errorf("error creating OperatorCommand: %v", err)
	}

	logger.L().Info("update rules command sent")
	return nil
}
