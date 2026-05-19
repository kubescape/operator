package v1

import (
	"k8s.io/apimachinery/pkg/runtime"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SecurityExceptionMatch struct {
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	ObjectSelector    *metav1.LabelSelector `json:"objectSelector,omitempty"`
	Resources         []ResourceMatch       `json:"resources,omitempty"`
	Images            []string              `json:"images,omitempty"`
}

type ResourceMatch struct {
	APIGroup string `json:"apiGroup,omitempty"`
	Kind     string `json:"kind"`
	Name     string `json:"name,omitempty"`
}

type VulnerabilityReference struct {
	ID string `json:"id,omitempty"`
}

type VulnerabilityException struct {
	Vulnerability VulnerabilityReference `json:"vulnerability,omitempty"`
	Status        string                `json:"status,omitempty"`
	ExpiredOnFix  *bool                 `json:"expiredOnFix,omitempty"`
}

type PostureException struct {
	ControlID string `json:"controlID,omitempty"`
	Action    string `json:"action,omitempty"`
}

type SecurityExceptionSpec struct {
	Author          string                   `json:"author,omitempty"`
	Reason          string                   `json:"reason,omitempty"`
	ExpiresAt       *metav1.Time             `json:"expiresAt,omitempty"`
	Match           *SecurityExceptionMatch  `json:"match,omitempty"`
	Vulnerabilities []VulnerabilityException `json:"vulnerabilities,omitempty"`
	Posture         []PostureException       `json:"posture,omitempty"`
}

type SecurityException struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SecurityExceptionSpec `json:"spec"`
}

type SecurityExceptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityException `json:"items"`
}

type ClusterSecurityException struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SecurityExceptionSpec `json:"spec"`
}

type ClusterSecurityExceptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterSecurityException `json:"items"`
}

func init() {
	SchemeBuilder.Register(
		&SecurityException{},
		&SecurityExceptionList{},
		&ClusterSecurityException{},
		&ClusterSecurityExceptionList{},
	)
}

func (in *SecurityExceptionMatch) DeepCopyInto(out *SecurityExceptionMatch) {
	*out = *in
	if in.NamespaceSelector != nil {
		out.NamespaceSelector = in.NamespaceSelector.DeepCopy()
	}
	if in.ObjectSelector != nil {
		out.ObjectSelector = in.ObjectSelector.DeepCopy()
	}
	if in.Resources != nil {
		out.Resources = make([]ResourceMatch, len(in.Resources))
		copy(out.Resources, in.Resources)
	}
	if in.Images != nil {
		out.Images = make([]string, len(in.Images))
		copy(out.Images, in.Images)
	}
}

func (in *SecurityExceptionSpec) DeepCopyInto(out *SecurityExceptionSpec) {
	*out = *in
	if in.ExpiresAt != nil {
		copy := *in.ExpiresAt
		out.ExpiresAt = &copy
	}
	if in.Match != nil {
		out.Match = &SecurityExceptionMatch{}
		in.Match.DeepCopyInto(out.Match)
	}
	if in.Vulnerabilities != nil {
		out.Vulnerabilities = make([]VulnerabilityException, len(in.Vulnerabilities))
		copy(out.Vulnerabilities, in.Vulnerabilities)
	}
	if in.Posture != nil {
		out.Posture = make([]PostureException, len(in.Posture))
		copy(out.Posture, in.Posture)
	}
}

func (in *SecurityException) DeepCopyInto(out *SecurityException) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

func (in *SecurityException) DeepCopy() *SecurityException {
	if in == nil {
		return nil
	}
	out := new(SecurityException)
	in.DeepCopyInto(out)
	return out
}

func (in *SecurityException) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *SecurityExceptionList) DeepCopyInto(out *SecurityExceptionList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SecurityException, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *SecurityExceptionList) DeepCopy() *SecurityExceptionList {
	if in == nil {
		return nil
	}
	out := new(SecurityExceptionList)
	in.DeepCopyInto(out)
	return out
}

func (in *SecurityExceptionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *ClusterSecurityException) DeepCopyInto(out *ClusterSecurityException) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

func (in *ClusterSecurityException) DeepCopy() *ClusterSecurityException {
	if in == nil {
		return nil
	}
	out := new(ClusterSecurityException)
	in.DeepCopyInto(out)
	return out
}

func (in *ClusterSecurityException) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *ClusterSecurityExceptionList) DeepCopyInto(out *ClusterSecurityExceptionList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ClusterSecurityException, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *ClusterSecurityExceptionList) DeepCopy() *ClusterSecurityExceptionList {
	if in == nil {
		return nil
	}
	out := new(ClusterSecurityExceptionList)
	in.DeepCopyInto(out)
	return out
}

func (in *ClusterSecurityExceptionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
