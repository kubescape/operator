package mainhandler

import (
	"encoding/json"
	"k8s-ca-websocket/cacli"
	"testing"

	"github.com/armosec/capacketsgo/secrethandling"
	corev1 "k8s.io/api/core/v1"
)

var clearSecretMock = `{
    "apiVersion": "v1",
    "data": {
        "customer": "Q3liZXJBcm1vclRlc3Rz",
        "password": "bml1ZGhmMjgzcnUyM3JrZQ==",
        "username": "ZHdlcnRlbnRAY3liZXJhcm1vci5pbw=="
    },
    "kind": "Secret",
    "metadata": {
        "name": "encrypted-credentials-1",
        "namespace": "default"
    },
    "type": "Opaque"
}`

var encryptedSecretMock = `{
    "apiVersion": "v1",
    "data": {
        "customer": "58UY7QAAAEQAAAABAAAAAAAAAAQAAAAAwBNqGdzhRx8/uopZ+w9oPgAAAADAE2oZ3OFHHz+6iln7D2g+wBNqGdzhRx8AAAAAAAAAALt04IbgeEYzYtOUKxRGCQ==",
        "password": "58UY7QAAAEQAAAABAAAAAAAAAAQAAAAA1JCNItgW8nJTRSLEvvPz2gAAAADUkI0i2BbyclNFIsS+8/Pa1JCNItgW8nIAAAAAAAAAADOQukv1oFCsaNGUC35fdmQ=",
        "username": "58UY7QAAAEQAAAABAAAAAAAAAAQAAAAA+bbfzOnMkNs1RzvemZilMAAAAAD5tt/M6cyQ2zVHO96ZmKUw+bbfzOnMkNsAAAAAAAAAANVVlAxbziLhxJCeW0O7tt5ayRQqkfw="
    },
    "kind": "Secret",
    "metadata": {
        "name": "encrypted-credentials-1"
    },
    "type": "Opaque"
}`

func GetClearSecretMock() *corev1.Secret {
	secret := &corev1.Secret{}
	json.Unmarshal([]byte(clearSecretMock), secret)
	return secret
}

func GetEncryptedSecretMock() *corev1.Secret {
	secret := &corev1.Secret{}
	json.Unmarshal([]byte(encryptedSecretMock), secret)
	return secret
}

//NewSecretHandler -
func NewSecretHandlerMock(sid string) *SecretHandler {
	return &SecretHandler{
		cacli:         cacli.NewCacliMock(),
		sid:           sid,
		cluster:       secrethandling.GetSIDCluster(sid),
		namespace:     secrethandling.GetSIDNamespace(sid),
		secretName:    secrethandling.GetSIDName(sid),
		subsecretName: secrethandling.GetSIDSubsecret(sid),
	}

}
func TestGetFieldsToEncrypt(t *testing.T) {
	// sid := "sid://cluster-david-v1/namespace-default/secret-encrypted-credentials-1"
	// sech := NewSecretHandlerMock(sid)
	clearSecret := GetClearSecretMock()
	encryptedSecret := GetEncryptedSecretMock()

	fieldsToEncrypt, err := secrethandling.GetFieldsToEncrypt(clearSecret.Data, nil, "")
	if err != nil {
		t.Error(err)
	}
	if len(fieldsToEncrypt) != len(clearSecret.Data) {
		t.Errorf("expecting %d, received: %d", len(clearSecret.Data), len(fieldsToEncrypt))
	}

	fieldsToEncrypt2, err := secrethandling.GetFieldsToEncrypt(encryptedSecret.Data, nil, "")
	if err != nil {
		t.Error(err)
	}
	if len(fieldsToEncrypt2) != 0 {
		t.Errorf("expecting %d, received: %d", 0, len(fieldsToEncrypt2))
	}
}

func TestGetFieldsToDecrypt(t *testing.T) {
	// sid := "sid://cluster-david-v1/namespace-default/secret-encrypted-credentials-1"
	// sech := NewSecretHandlerMock(sid)
	clearSecret := GetClearSecretMock()
	encryptedSecret := GetEncryptedSecretMock()

	fieldsToDecrypt, err := secrethandling.GetFieldsToDecrypt(clearSecret.Data, "")
	if err != nil {
		t.Error(err)
	}
	if len(fieldsToDecrypt) != 0 {
		t.Errorf("expecting %d, received: %d", 0, len(fieldsToDecrypt))
	}

	fieldsToDecrypt2, err := secrethandling.GetFieldsToDecrypt(encryptedSecret.Data, "")
	if err != nil {
		t.Error(err)
	}
	if len(fieldsToDecrypt2) != len(encryptedSecret.Data) {
		t.Errorf("expecting %d, received: %d", len(encryptedSecret.Data), len(fieldsToDecrypt2))
	}
}
