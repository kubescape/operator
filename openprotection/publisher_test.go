package openprotection

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestConfigMapPublisherCreatesWhenAbsent(t *testing.T) {
	client := fake.NewSimpleClientset()
	p := NewConfigMapPublisher(client, "kubescape", "storage-open-protection")

	if err := p.Publish(context.Background(), `{"prefix":["/etc/shadow"]}`); err != nil {
		t.Fatalf("publish: %v", err)
	}
	cm, err := client.CoreV1().ConfigMaps("kubescape").Get(context.Background(), "storage-open-protection", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if cm.Data[ConfigMapKey] != `{"prefix":["/etc/shadow"]}` {
		t.Errorf("unexpected data: %q", cm.Data[ConfigMapKey])
	}
	if cm.Labels[managedByLabelKey] != managedByLabelValue {
		t.Errorf("expected managed-by label, got %v", cm.Labels)
	}
}

func TestConfigMapPublisherUpdatesExisting(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "storage-open-protection"},
		Data:       map[string]string{ConfigMapKey: `{"prefix":["/old"]}`, "keepme": "yes"},
	})
	p := NewConfigMapPublisher(client, "kubescape", "storage-open-protection")

	if err := p.Publish(context.Background(), `{"prefix":["/new"]}`); err != nil {
		t.Fatalf("publish: %v", err)
	}
	cm, _ := client.CoreV1().ConfigMaps("kubescape").Get(context.Background(), "storage-open-protection", metav1.GetOptions{})
	if cm.Data[ConfigMapKey] != `{"prefix":["/new"]}` {
		t.Errorf("expected updated payload, got %q", cm.Data[ConfigMapKey])
	}
	if cm.Data["keepme"] != "yes" {
		t.Errorf("publisher clobbered unrelated key")
	}
}

func TestConfigMapPublisherSkipsUnchanged(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "storage-open-protection", ResourceVersion: "7"},
		Data:       map[string]string{ConfigMapKey: `{"prefix":["/same"]}`},
	})
	p := NewConfigMapPublisher(client, "kubescape", "storage-open-protection")

	if err := p.Publish(context.Background(), `{"prefix":["/same"]}`); err != nil {
		t.Fatalf("publish: %v", err)
	}
	cm, _ := client.CoreV1().ConfigMaps("kubescape").Get(context.Background(), "storage-open-protection", metav1.GetOptions{})
	if cm.ResourceVersion != "7" {
		t.Errorf("expected no write for unchanged payload (resourceVersion bumped to %s)", cm.ResourceVersion)
	}
}
