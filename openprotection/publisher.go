package openprotection

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ConfigMapKey is the key under which the open-protection union JSON is stored.
// It MUST match the storage apiserver's reader constant
// (file.OpenProtectionConfigMapKey = "openProtection"); the two repos agree on
// this string by convention since storage cannot import the operator.
const ConfigMapKey = "openProtection"

// managedByLabel marks the ConfigMap as operator-owned so it is easy to identify
// and so we never clobber an unrelated ConfigMap of the same name.
const (
	managedByLabelKey   = "app.kubernetes.io/managed-by"
	managedByLabelValue = "operator-open-protection"
)

// Publisher writes the open-protection union into a ConfigMap that the storage
// apiserver polls. It is the sink side of the watcher: the watcher computes the
// union from active rule bindings, the publisher reconciles it into the cluster.
type Publisher interface {
	Publish(ctx context.Context, payload string) error
}

// ConfigMapPublisher reconciles a single ConfigMap (namespace/name) so its
// ConfigMapKey entry equals payload, creating the ConfigMap if absent and
// skipping the write when already up to date.
type ConfigMapPublisher struct {
	client    kubernetes.Interface
	namespace string
	name      string
}

var _ Publisher = (*ConfigMapPublisher)(nil)

func NewConfigMapPublisher(client kubernetes.Interface, namespace, name string) *ConfigMapPublisher {
	return &ConfigMapPublisher{client: client, namespace: namespace, name: name}
}

func (p *ConfigMapPublisher) Publish(ctx context.Context, payload string) error {
	cms := p.client.CoreV1().ConfigMaps(p.namespace)
	cm, err := cms.Get(ctx, p.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cms.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      p.name,
				Namespace: p.namespace,
				Labels:    map[string]string{managedByLabelKey: managedByLabelValue},
			},
			Data: map[string]string{ConfigMapKey: payload},
		}, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if cm.Data[ConfigMapKey] == payload {
		// already up to date — avoid a no-op write (and a needless resourceVersion bump)
		return nil
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[ConfigMapKey] = payload
	_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
	return err
}
