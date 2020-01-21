package cautils

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/golang/glog"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

var (
	WlidPrefix          = "wlid://"
	ClusterWlidPrefix   = "cluster-"
	NamespaceWlidPrefix = "namespace-"
)

// GetWLID get the calculated wlid
func GetWLID(level0, level1, k, name string) string {
	kind := strings.ToLower(k)
	kind = strings.Replace(kind, "-", "", -1)
	return fmt.Sprintf("%s%s%s/%s%s/%s-%s", WlidPrefix, ClusterWlidPrefix, level0, NamespaceWlidPrefix, level1, kind, name)

}

// RunCommand -
func RunCommand(command string, arg []string, display bool) (*exec.Cmd, error) {
	var outb, errb bytes.Buffer
	var cancel context.CancelFunc

	// adding timeout
	ctx := context.Background()
	ctx, cancel = context.WithTimeout(context.Background(), time.Duration(120)*time.Second)
	defer cancel()

	if display {
		glog.Infof("Running: %s %v", command, arg)
	}

	cmd := exec.CommandContext(ctx, command, arg...)

	// cmd := exec.Command(command, arg...)
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()
	return cmd, err
}

// GetNamespaceFromWorkload extrac namespace from workload
func GetNamespaceFromWorkload(workload interface{}) string {
	if w, k := workload.(*appsv1.Deployment); k {
		return w.ObjectMeta.Namespace
	}
	if w, k := workload.(*appsv1.DaemonSet); k {
		return w.ObjectMeta.Namespace
	}
	if w, k := workload.(*appsv1.ReplicaSet); k {
		return w.ObjectMeta.Namespace
	}
	if w, k := workload.(*appsv1.StatefulSet); k {
		return w.ObjectMeta.Namespace
	}
	if w, k := workload.(*corev1.PodTemplate); k {
		return w.ObjectMeta.Namespace
	}
	if w, k := workload.(*corev1.Pod); k {
		return w.ObjectMeta.Namespace
	}

	return "default"
}
