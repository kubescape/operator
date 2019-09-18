package cautils

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func EncodedSecret() (sec corev1.Secret) {
	cred := map[string][]byte{
		"username": []byte("dXNlcg=="), // user
		"password": []byte("cHdk"),     //pwd
	}
	sec.Data = cred
	sec.Type = "Opaque"

	sec.ObjectMeta = metav1.ObjectMeta{Name: "mysecret", Namespace: "cyberarmor-system"}

	return sec
}

func TestSecrets(t *testing.T) {
	sec := EncodedSecret()
	st, err := GetSecretContent(&sec)
	if err != nil {
		t.Error(err)
	}
	outh, err := ReadSecret(st, sec.ObjectMeta.Name)
	if err != nil {
		t.Error(err)
	}
	if outh.Username != "user" || outh.Password != "pwd" {
		t.Errorf("wrong user name or password")
	}

}
