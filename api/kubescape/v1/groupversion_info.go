package v1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

const (
	Group   = "kubescape.io"
	Version = "v1"

	SecurityExceptionKind        = "SecurityException"
	ClusterSecurityExceptionKind = "ClusterSecurityException"
)

var GroupVersion = schema.GroupVersion{Group: Group, Version: Version}

var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

var AddToScheme = SchemeBuilder.AddToScheme
