package mainhandler

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"k8s-ca-websocket/cacli"
	"k8s-ca-websocket/cautils"
	"math/rand"
	"os"

	pkgcautils "github.com/armosec/capacketsgo/cautils"

	"github.com/armosec/capacketsgo/apis"
	"github.com/armosec/capacketsgo/secrethandling"
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
// func NewSecretHandler(sid string) *SecretHandler {
// 	return &SecretHandler{
// 		cacli:         cacli.NewCacli(),
// 		sid:           sid,
// 		cluster:       secrethandling.GetSIDCluster(sid),
// 		namespace:     secrethandling.GetSIDNamespace(sid),
// 		secretName:    secrethandling.GetSIDName(sid),
// 		subsecretName: secrethandling.GetSIDSubsecret(sid),
// 	}

// }

func (actionHandler *ActionHandler) runSecretCommand(sessionObj *cautils.SessionObj) error {
	c := sessionObj.Command

	if actionHandler.sid == "" {
		sid, err := getSIDFromArgs(c.Args)
		if err != nil {
			return err
		}
		actionHandler.sid = sid
	}

	if err := secrethandling.ValidateSecretID(actionHandler.sid); err != nil {
		return err
	}

	if pkgcautils.IfIgnoreNamespace(secrethandling.GetSIDNamespace(actionHandler.sid)) {
		glog.Infof("Ignoring sid: '%s'", actionHandler.sid)
		return nil
	}

	switch c.CommandName {
	case apis.ENCRYPT:
		return actionHandler.encryptSecret()
	case apis.DECRYPT, apis.UNREGISTERED: // todo - support UNREGISTERED
		return actionHandler.decryptSecret()
	}
	return nil
}
func (actionHandler *ActionHandler) encryptSecret() error {
	// get secret
	secret, err := actionHandler.GetSecret(secrethandling.GetSIDNamespace(actionHandler.sid), secrethandling.GetSIDName(actionHandler.sid))
	if err != nil {
		return err
	}

	if !secrethandling.IsSecretTypeSupported(secret.Type) {
		glog.Warningf("secret type '%s' not supported", secret.Type)
		return nil
	}

	if secret.Data == nil || len(secret.Data) == 0 {
		return fmt.Errorf("no data in secret to encrypt")
	}

	secretPolicyList, err := actionHandler.cacli.SECPGet(actionHandler.sid, "", "", "")
	if err != nil {
		return err
	}
	if len(secretPolicyList) == 0 {
		return fmt.Errorf("somthing went wrong, no secret policy found for secret-id: '%s'", actionHandler.sid)
	}
	secretPolicy := secretPolicyList[0]

	// set subsecret fields to encrypt
	fieldsToEncrypt, err := secrethandling.GetFieldsToEncrypt(secret.Data, &secretPolicy, secrethandling.GetSIDSubsecret(actionHandler.sid))
	if err != nil {
		return err
	}

	updateSecret := false

	// encrypt subsecret/s
	for subsecretName, keyID := range fieldsToEncrypt {
		if err := actionHandler.encryptSubsecret(secret.Data, subsecretName, keyID); err != nil {
			return err
		}
		updateSecret = true
	}

	// update secret
	if updateSecret {
		glog.Infof("updating secret: %s", actionHandler.sid)
		if err := actionHandler.UpdateSecret(secret, apis.ENCRYPT); err != nil {
			return err
		}
	}

	return nil
}

func (actionHandler *ActionHandler) decryptSecret() error {
	// get secret
	secret, err := actionHandler.GetSecret(secrethandling.GetSIDNamespace(actionHandler.sid), secrethandling.GetSIDName(actionHandler.sid))
	if err != nil {
		return err
	}
	if !secrethandling.IsSecretTypeSupported(secret.Type) {
		glog.Warningf("secret type '%s' not supported", secret.Type)
		return nil
	}

	//check if subsecret is in secret
	if secret.Data == nil || len(secret.Data) == 0 {
		return fmt.Errorf("no data in secret to encrypt")
	}

	fieldsToDecrypt, err := secrethandling.GetFieldsToDecrypt(secret.Data, secrethandling.GetSIDSubsecret(actionHandler.sid))
	if err != nil {
		return err
	}

	updateSecret := false

	// encrypt subsecret/s
	for i := range fieldsToDecrypt {
		if err := actionHandler.decryptSubsecret(secret.Data, fieldsToDecrypt[i]); err != nil {
			return err
		}
		updateSecret = true
	}

	// update secret
	if updateSecret {
		glog.Infof("updating secret: %s", actionHandler.sid)
		if err := actionHandler.UpdateSecret(secret, apis.DECRYPT); err != nil {
			return err
		}
	}

	// remove shadow secret
	shadowSecret := secrethandling.ArmoShadowSecretPrefix + secrethandling.GetSIDName(actionHandler.sid)
	if err := actionHandler.DeleteSecret(secrethandling.GetSIDNamespace(actionHandler.sid), secrethandling.ArmoShadowSecretPrefix+secrethandling.GetSIDName(actionHandler.sid)); err != nil {
		return fmt.Errorf("failed removing shadow secret %s, reason: %s", shadowSecret, err.Error())
	}

	return nil
}

func (actionHandler *ActionHandler) encryptSubsecret(secretDate map[string][]byte, subsecret string, keyID string) error {
	glog.Infof("Encrypting subsecret '%s', sid: '%s'", subsecret, actionHandler.sid)

	tmpFileName := fmt.Sprintf("/tmp/enc-%s.%s.%s.%d", secrethandling.GetSIDNamespace(actionHandler.sid), secrethandling.GetSIDName(actionHandler.sid), subsecret, rand.Int())
	_, err := actionHandler.cacli.SECPEncrypt(string(secretDate[subsecret]), "", tmpFileName, keyID, false)

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

func (actionHandler *ActionHandler) decryptSubsecret(secretDate map[string][]byte, subsecret string) error {
	glog.Infof("decrypting subsecret '%s', sid: '%s'", subsecret, actionHandler.sid)

	tmpFileName := fmt.Sprintf("/tmp/dec-%s.%s.%s.%d", secrethandling.GetSIDNamespace(actionHandler.sid), secrethandling.GetSIDName(actionHandler.sid), subsecret, rand.Int())
	if err := ioutil.WriteFile(tmpFileName, []byte(base64.StdEncoding.EncodeToString(secretDate[subsecret])), 0644); err != nil {
		return err
	}
	decryptedData, err := actionHandler.cacli.SECPDecrypt("", tmpFileName, "", true)
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

func getSIDFromArgs(args map[string]interface{}) (string, error) {
	sidInterface, ok := args["sid"]
	if !ok {
		return "", nil
	}
	sid, ok := sidInterface.(string)
	if !ok || sid == "" {
		return "", fmt.Errorf("sid found in args but empty")
	}
	if _, err := secrethandling.SplitSecretID(sid); err != nil {
		return "", err
	}
	return sid, nil
}
