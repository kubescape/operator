package websocket

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"k8s-ca-websocket/cacli"
	"math/rand"
	"os"

	"asterix.cyberarmor.io/cyberarmor/capacketsgo/secrethandling"
	"github.com/golang/glog"
)

// SecretHandler -
type SecretHandler struct {
	cacli         cacli.ICacli
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

func (secretHandler *SecretHandler) encryptSecret() error {
	// get secret
	secret, err := GetSecret(secretHandler.namespace, secretHandler.secretName)
	if err != nil {
		return err
	}

	if secret.Data == nil || len(secret.Data) == 0 {
		return fmt.Errorf("no data in secret to encrypt")
	}

	secretPolicyList, err := secretHandler.cacli.GetSecretAccessPolicy(secretHandler.sid, "", "", "")
	if err != nil {
		return err
	}
	if len(secretPolicyList) == 0 {
		return fmt.Errorf("somthing went wrong, no secret policy found for secret-id: '%s'", secretHandler.sid)
	}
	secretPolicy := secretPolicyList[0]

	// set subsecret fields to encrypt
	fieldsToEncrypt, err := secretHandler.getFieldsToEncrypt(secret.Data, &secretPolicy)
	if err != nil {
		return err
	}

	updateSecret := false

	// encrypt subsecret/s
	for subsecretName, keyID := range fieldsToEncrypt {
		if err := secretHandler.encryptSubsecret(secret.Data, subsecretName, keyID); err != nil {
			return err
		}
		updateSecret = true
	}

	// update secret
	if updateSecret {
		glog.Infof("updating secret: %s", secretHandler.sid)
		if err := UpdateSecret(secret); err != nil {
			return err
		}
	}

	return nil
}

func (secretHandler *SecretHandler) decryptSecret() error {
	// get secret
	secret, err := GetSecret(secretHandler.namespace, secretHandler.secretName)
	if err != nil {
		return err
	}

	//check if subsecret is in secret
	if secret.Data == nil || len(secret.Data) == 0 {
		return fmt.Errorf("no data in secret to encrypt")
	}

	fieldsToDecrypt, err := secretHandler.getFieldsToDecrypt(secret.Data)
	if err != nil {
		return err
	}

	updateSecret := false

	// encrypt subsecret/s
	for i := range fieldsToDecrypt {
		if err := secretHandler.decryptSubsecret(secret.Data, fieldsToDecrypt[i]); err != nil {
			return err
		}
		updateSecret = true
	}

	// update secret
	if updateSecret {
		glog.Infof("updating secret: %s", secretHandler.sid)
		if err := UpdateSecret(secret); err != nil {
			return err
		}
	}

	// remove shadow secret
	shadowSecret := secrethandling.ArmoShadowSecretPrefix + secretHandler.secretName
	if err := DeleteSecret(secretHandler.namespace, secrethandling.ArmoShadowSecretPrefix+secretHandler.secretName); err != nil {
		return fmt.Errorf("failed removing shadow secret %s, reason: %s", shadowSecret, err.Error())
	}

	return nil
}

func (secretHandler *SecretHandler) encryptSubsecret(secretDate map[string][]byte, subsecret string, keyID string) error {
	glog.Infof("encrypting subsecret '%s', sid: '%s'", subsecret, secretHandler.sid)

	tmpFileName := fmt.Sprintf("/tmp/enc-%s.%s.%s.%d", secretHandler.namespace, secretHandler.secretName, subsecret, rand.Int())
	_, err := secretHandler.cacli.SecretEncrypt(string(secretDate[subsecret]), "", tmpFileName, keyID, false)

	encryptedData, err := ioutil.ReadFile(tmpFileName)
	if err != nil {
		return err
	}
	secretDate[subsecret] = encryptedData

	if err := os.Remove(tmpFileName); err != nil {
		glog.Errorf("cant remove tmp file: %s", err.Error())
	}
	return nil
}

func (secretHandler *SecretHandler) decryptSubsecret(secretDate map[string][]byte, subsecret string) error {
	glog.Infof("decrypting subsecret '%s', sid: '%s'", subsecret, secretHandler.sid)

	tmpFileName := fmt.Sprintf("/tmp/dec-%s.%s.%s.%d", secretHandler.namespace, secretHandler.secretName, subsecret, rand.Int())
	if err := ioutil.WriteFile(tmpFileName, []byte(base64.StdEncoding.EncodeToString(secretDate[subsecret])), 0644); err != nil {
		return err
	}
	decryptedData, err := secretHandler.cacli.SecretDecrypt("", tmpFileName, "", true)
	if err != nil {
		return err
	}
	decodeDecryptedData, err := base64.StdEncoding.DecodeString(string(decryptedData))
	if err != nil {
		return err
	}
	secretDate[subsecret] = decodeDecryptedData

	if err := os.Remove(tmpFileName); err != nil {
		glog.Errorf("cant remove tmp file: %s", err.Error())
	}
	return nil
}

func (secretHandler *SecretHandler) getFieldsToEncrypt(secretDate map[string][]byte, secretPolicy *secrethandling.SecretAccessPolicy) (map[string]string, error) {
	fieldsToEncrypt, err := secretHandler.getFieldsToEncryptFromSecretPolicy(secretDate, secretPolicy)
	if err != nil || len(fieldsToEncrypt) != 0 { // if subsecrets are defined in secret policy
		return fieldsToEncrypt, err
	}

	// if secret policy doesn't have subsecrets
	if secretHandler.subsecretName != "" {
		secretData, ok := secretDate[secretHandler.subsecretName]
		if !ok {
			return fieldsToEncrypt, fmt.Errorf("subsecret %s not found in sid '%s' data", secretHandler.subsecretName, secretHandler.sid)
		}
		if !secrethandling.HasSecretTLV(secretData) {
			fieldsToEncrypt[secretHandler.subsecretName] = ""
		}
	} else {
		for subsecret, secretData := range secretDate {
			if !secrethandling.HasSecretTLV(secretData) {
				fieldsToEncrypt[subsecret] = ""
			}
		}

	}
	return fieldsToEncrypt, nil
}

func (secretHandler *SecretHandler) getFieldsToDecrypt(secretDate map[string][]byte) ([]string, error) {
	fieldsToDecrypt := []string{}

	if secretHandler.subsecretName != "" {
		secretData, ok := secretDate[secretHandler.subsecretName]
		if !ok {
			return fieldsToDecrypt, fmt.Errorf("subsecret %s not found in sid '%s' data", secretHandler.subsecretName, secretHandler.sid)
		}
		if secrethandling.HasSecretTLV(secretData) {
			fieldsToDecrypt = append(fieldsToDecrypt, secretHandler.subsecretName)
		}
	} else {
		for subsecret, secretData := range secretDate {
			if secrethandling.HasSecretTLV(secretData) {
				fieldsToDecrypt = append(fieldsToDecrypt, subsecret)
			}
		}

	}
	return fieldsToDecrypt, nil
}

func (secretHandler *SecretHandler) getFieldsToEncryptFromSecretPolicy(secretDate map[string][]byte, secretPolicy *secrethandling.SecretAccessPolicy) (map[string]string, error) {
	fieldsToEncrypt := make(map[string]string)
	if secretPolicy == nil || secretPolicy.Secrets == nil {
		return fieldsToEncrypt, nil
	}
	for secrets := range secretPolicy.Secrets {
		for _, subsecret := range secretPolicy.Secrets[secrets].KeyIDs {
			secretData, ok := secretDate[subsecret.SubSecretName]
			if !ok {
				return fieldsToEncrypt, fmt.Errorf("subsecret %s not found in sid '%s' data", secretHandler.subsecretName, secretHandler.sid)
			}
			if !secrethandling.HasSecretTLV(secretData) {
				fieldsToEncrypt[subsecret.SubSecretName] = subsecret.KeyID
			}
		}
	}
	return fieldsToEncrypt, nil
}
