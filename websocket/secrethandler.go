package websocket

import (
	"fmt"
	"k8s-ca-websocket/cacli"

	"asterix.cyberarmor.io/cyberarmor/capacketsgo/secrethandling"
)

// SecretHandler -
type SecretHandler struct {
	cacli         *cacli.Cacli
	sid           string
	cluster       string
	namespace     string
	secretName    string
	subsecretName string
}

//NewSecretHandler -
func NewSecretHandler(sid string) *SecretHandler {
	return &SecretHandler{
		cacli:         cacli.NewCacli(),
		sid:           sid,
		cluster:       secrethandling.GetSIDCluster(sid),
		namespace:     secrethandling.GetSIDNamespace(sid),
		secretName:    secrethandling.GetSIDName(sid),
		subsecretName: secrethandling.GetSIDSubsecret(sid),
	}

}

func (secretHandler *SecretHandler) encryptSecret(sid string) error {
	// get secret
	secret, err := GetSecret(secretHandler.namespace, secretHandler.secretName)
	if err != nil {
		return err
	}

	//check if subsecret is in secret
	if secret.Data == nil || len(secret.Data) == 0 {
		return fmt.Errorf("no data in secret to encrypt")
	}

	fieldsToEncrypt := []string{}
	if secretHandler.subsecretName != "" {
		if _, ok := secret.Data[secretHandler.subsecretName]; !ok {
			return fmt.Errorf("subsecret %s not found in secret %s data", secretHandler.subsecretName, secret.Name)
		}
		fieldsToEncrypt = append(fieldsToEncrypt, secretHandler.subsecretName)
	} else {
		for subsecret := range secret.Data {
			fieldsToEncrypt = append(fieldsToEncrypt, subsecret)
		}
	}

	// encrpyt subsecret/s
	for i := range fieldsToEncrypt {
		encryptedData, err := secretHandler.cacli.SecretEncrypt(string(secret.Data[fieldsToEncrypt[i]]))
		if err != nil {
			return err
		}
		secret.Data[fieldsToEncrypt[i]] = encryptedData
	}

	// update secret
	if err := UpdateSecret(secret); err != nil {
		return err
	}

	return nil
}

func (secretHandler *SecretHandler) decryptSecret(sid string) error {
	// get secret
	secret, err := GetSecret(secretHandler.namespace, secretHandler.secretName)
	if err != nil {
		return err
	}

	//check if subsecret is in secret
	if secret.Data == nil || len(secret.Data) == 0 {
		return fmt.Errorf("no data in secret to encrypt")
	}

	fieldsToDecrypt := []string{}
	if secretHandler.subsecretName != "" {
		if _, ok := secret.Data[secretHandler.subsecretName]; !ok {
			return fmt.Errorf("subsecret %s not found in secret %s data", secretHandler.subsecretName, secret.Name)
		}
		fieldsToDecrypt = append(fieldsToDecrypt, secretHandler.subsecretName)
	} else {
		for subsecret := range secret.Data {
			fieldsToDecrypt = append(fieldsToDecrypt, subsecret)
		}
	}

	// encrpyt subsecret/s
	for i := range fieldsToDecrypt {
		decryptedData, err := secretHandler.cacli.SecretDecrypt(string(secret.Data[fieldsToDecrypt[i]]))
		if err != nil {
			return err
		}
		secret.Data[fieldsToDecrypt[i]] = decryptedData
	}

	// update secret
	if err := UpdateSecret(secret); err != nil {
		return err
	}

	return nil
}
