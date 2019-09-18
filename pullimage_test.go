package main

import (
	"encoding/json"
	"k8s-ca-webhook/cautils"
	"os"
	"testing"

	"github.com/docker/docker/api/types"
	corev1 "k8s.io/api/core/v1"
)

var (
	tJSONSecret = `{"metadata":{"name":"caregcred","namespace":"cyberarmor-system","selfLink":"/api/v1/namespaces/cyberarmor-system/secrets/caregcred","uid":"6f41c1cf-52f1-42a9-ba53-8086c1d3620d","resourceVersion":"11289","creationTimestamp":"2019-09-02T08:25:08Z","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"data\":{\".dockerconfigjson\":\"eyJhdXRocyI6eyJkcmVnLmV1c3QwLmN5YmVyYXJtb3Jzb2Z0LmNvbTo0NDMiOnsidXNlcm5hbWUiOiJjYXVzZXIiLCJwYXNzd29yZCI6ImpZMzVzbzlnIiwiZW1haWwiOiJiaGlyc2NoYkBjeWJlcmFybW9yLmlvIiwiYXV0aCI6IlkyRjFjMlZ5T21wWk16VnpiemxuIn19fQ==\"},\"kind\":\"Secret\",\"metadata\":{\"annotations\":{},\"name\":\"caregcred\",\"namespace\":\"cyberarmor-system\",\"selfLink\":\"/api/v1/namespaces/cyberarmor-system/secrets/caregcred\"},\"type\":\"kubernetes.io/dockerconfigjson\"}\n"}},"data":{".dockerconfigjson":"eyJhdXRocyI6eyJkcmVnLmV1c3QwLmN5YmVyYXJtb3Jzb2Z0LmNvbTo0NDMiOnsidXNlcm5hbWUiOiJjYXVzZXIiLCJwYXNzd29yZCI6ImpZMzVzbzlnIiwiZW1haWwiOiJiaGlyc2NoYkBjeWJlcmFybW9yLmlvIiwiYXV0aCI6IlkyRjFjMlZ5T21wWk16VnpiemxuIn19fQ=="},"type":"kubernetes.io/dockerconfigjson"}`
	tJSONPod    = `{"metadata":{"name":"ca-webhook-deployment-577fd69f5-qkwt5","generateName":"ca-webhook-deployment-577fd69f5-","namespace":"cyberarmor-system","selfLink":"/api/v1/namespaces/cyberarmor-system/pods/ca-webhook-deployment-577fd69f5-qkwt5","uid":"6a282c64-5e09-48a6-861b-ea7445fdcb37","resourceVersion":"11380","creationTimestamp":"2019-09-02T08:25:09Z","labels":{"app":"ca-webhook","pod-template-hash":"577fd69f5"},"ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"ca-webhook-deployment-577fd69f5","uid":"5c704a9a-c02e-4c13-abe7-564542367968","controller":true,"blockOwnerDeletion":true}]},"spec":{"volumes":[{"name":"docker-socket-volume","hostPath":{"path":"/var/run/docker.sock","type":"File"}},{"name":"ca-controller-certs","secret":{"secretName":"ca-controller-certs","defaultMode":420}},{"name":"ca-controller-service-account-token-4k5n8","secret":{"secretName":"ca-controller-service-account-token-4k5n8","defaultMode":420}}],"containers":[{"name":"ca-controller-webhook","image":"dreg.eust0.cyberarmorsoft.com:443/k8s-ca-webhook:latest","args":["-tlsCertFile=/etc/webhook/certs/cert.pem","-tlsKeyFile=/etc/webhook/certs/key.pem","-alsologtostderr","-v=4","2\u003e\u00261"],"env":[{"name":"CA_SERVICE_NAME","value":"ca-controller-service"},{"name":"CA_SERVICE_PORT","value":"443"},{"name":"CA_NAMESPACE","value":"cyberarmor-system"},{"name":"CA_PORATL_BACKEND","value":"https://caportalbe.eudev2.cyberarmorsoft.com"},{"name":"CA_CLUSTER_NAME","value":"minikube"},{"name":"CA_POSTMAN","value":"postman.eudev2.cyberarmorsoft.com"},{"name":"CA_CUSTOMER_GUID","value":"1e3a88bf-92ce-44f8-914e-cbe71830d566"}],"resources":{},"volumeMounts":[{"name":"docker-socket-volume","mountPath":"/var/run/docker.sock"},{"name":"ca-controller-certs","readOnly":true,"mountPath":"/etc/webhook/certs"},{"name":"ca-controller-service-account-token-4k5n8","readOnly":true,"mountPath":"/var/run/secrets/kubernetes.io/serviceaccount"}],"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","imagePullPolicy":"Always"}],"restartPolicy":"Always","terminationGracePeriodSeconds":30,"dnsPolicy":"ClusterFirst","serviceAccountName":"ca-controller-service-account","serviceAccount":"ca-controller-service-account","nodeName":"minikube","securityContext":{},"imagePullSecrets":[{"name":"caregcred"}],"schedulerName":"default-scheduler","tolerations":[{"key":"node.kubernetes.io/not-ready","operator":"Exists","effect":"NoExecute","tolerationSeconds":300},{"key":"node.kubernetes.io/unreachable","operator":"Exists","effect":"NoExecute","tolerationSeconds":300}],"priority":0,"enableServiceLinks":true},"status":{"phase":"Running","conditions":[{"type":"Initialized","status":"True","lastProbeTime":null,"lastTransitionTime":"2019-09-02T08:25:09Z"},{"type":"Ready","status":"True","lastProbeTime":null,"lastTransitionTime":"2019-09-02T08:25:21Z"},{"type":"ContainersReady","status":"True","lastProbeTime":null,"lastTransitionTime":"2019-09-02T08:25:21Z"},{"type":"PodScheduled","status":"True","lastProbeTime":null,"lastTransitionTime":"2019-09-02T08:25:09Z"}],"hostIP":"10.0.2.15","podIP":"172.17.0.6","startTime":"2019-09-02T08:25:09Z","containerStatuses":[{"name":"ca-controller-webhook","state":{"running":{"startedAt":"2019-09-02T08:25:20Z"}},"lastState":{},"ready":true,"restartCount":0,"image":"dreg.eust0.cyberarmorsoft.com:443/k8s-ca-webhook:latest","imageID":"docker-pullable://dreg.eust0.cyberarmorsoft.com:443/k8s-ca-webhook@sha256:41fa786327cddd52316afa0598f8a45749a811196a80e13f5256e6846bed6b7f","containerID":"docker://8cb1b7a613fdd999866e2e50db1be87e6c51b69f2ac00fcb202c74ccc4fa23f1"}],"qosClass":"BestEffort"}}`
)

func TestGetImagePullSecret(t *testing.T) {
	if d := os.Getenv("WEBHOOKDEBUG"); d == "" {
		return
	}

	pod := corev1.Pod{}
	if err := json.Unmarshal([]byte(tJSONSecret), &pod); err != nil {
		t.Error(err)
	}
	kd := kubernetesData{kubeconfig: cautils.LoadConfig()}

	secrets, err := kd.getImagePullSecret()
	if err != nil {
		t.Errorf("%v", err)
	}
	if sec, ok := secrets["caregcred"]; ok {
		if sec.Username != "causer" {
			t.Errorf("Wrong username")
		}
	} else {
		t.Errorf("Error parsing secret")
	}
}

func TestGetSecretContent(t *testing.T) {
	s := corev1.Secret{}
	if err := json.Unmarshal([]byte(tJSONSecret), &s); err != nil {
		t.Error(err)
	}
	inter, err := cautils.GetSecretContent(&s)
	if err != nil {
		t.Error(err)
	}
	secrets := map[string]types.AuthConfig{}
	secrets["caregcred"], _ = cautils.ReadSecret(inter, "caregcred")
	if sec, ok := secrets["caregcred"]; ok {
		if sec.Username != "causer" {
			t.Errorf("Wrong username")
		}
	} else {
		t.Errorf("Error parsing secret")
	}
}
