package sign

import (
	"encoding/json"
	"k8s-ca-websocket/k8sworkloads"
	"testing"

	"github.com/docker/docker/api/types"
	corev1 "k8s.io/api/core/v1"
)

var (
	tJSONSecret = `{"metadata":{"name":"caregcred","namespace":"cyberarmor-system","selfLink":"/api/v1/namespaces/cyberarmor-system/secrets/caregcred","uid":"6f41c1cf-52f1-42a9-ba53-8086c1d3620d","resourceVersion":"11289","creationTimestamp":"2019-09-02T08:25:08Z","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"data\":{\".dockerconfigjson\":\"eyJhdXRocyI6eyJkcmVnLmV1c3QwLmN5YmVyYXJtb3Jzb2Z0LmNvbTo0NDMiOnsidXNlcm5hbWUiOiJjYXVzZXIiLCJwYXNzd29yZCI6ImpZMzVzbzlnIiwiZW1haWwiOiJiaGlyc2NoYkBjeWJlcmFybW9yLmlvIiwiYXV0aCI6IlkyRjFjMlZ5T21wWk16VnpiemxuIn19fQ==\"},\"kind\":\"Secret\",\"metadata\":{\"annotations\":{},\"name\":\"caregcred\",\"namespace\":\"cyberarmor-system\",\"selfLink\":\"/api/v1/namespaces/cyberarmor-system/secrets/caregcred\"},\"type\":\"kubernetes.io/dockerconfigjson\"}\n"}},"data":{".dockerconfigjson":"eyJhdXRocyI6eyJkcmVnLmV1c3QwLmN5YmVyYXJtb3Jzb2Z0LmNvbTo0NDMiOnsidXNlcm5hbWUiOiJjYXVzZXIiLCJwYXNzd29yZCI6ImpZMzVzbzlnIiwiZW1haWwiOiJiaGlyc2NoYkBjeWJlcmFybW9yLmlvIiwiYXV0aCI6IlkyRjFjMlZ5T21wWk16VnpiemxuIn19fQ=="},"type":"kubernetes.io/dockerconfigjson"}`
)

func TestGetSecretContent(t *testing.T) {
	s := corev1.Secret{}
	if err := json.Unmarshal([]byte(tJSONSecret), &s); err != nil {
		t.Error(err)
	}
	inter, err := k8sworkloads.GetSecretContent(&s)
	if err != nil {
		t.Error(err)
	}
	secrets := map[string]types.AuthConfig{}
	secrets["caregcred"], _ = k8sworkloads.ReadSecret(inter, "caregcred")
	if sec, ok := secrets["caregcred"]; ok {
		if sec.Username != "causer" {
			t.Errorf("Wrong username")
		}
	} else {
		t.Errorf("Error parsing secret")
	}
}
