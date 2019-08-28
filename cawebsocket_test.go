package main

import (
	"fmt"
	"log"
	"net/url"
	"testing"

	"github.com/gorilla/websocket"
)

// var rec = "{\"commands\":[{\"commandName\":\"update\",\"responseID\":\"123\",\"kind\":\"\",\"args\":{\"json\":\"{\\\"metadata\\\":{\\\"annotations\\\":{\\\"deployment.kubernetes.io/revision\\\":\\\"1\\\",\\\"kubectl.kubernetes.io/last-applied-configuration\\\":\\\"{\\\\\\\"apiVersion\\\\\\\":\\\\\\\"apps/v1\\\\\\\",\\\\\\\"kind\\\\\\\":\\\\\\\"Deployment\\\\\\\",\\\\\\\"metadata\\\\\\\":{\\\\\\\"annotations\\\\\\\":{},\\\\\\\"name\\\\\\\":\\\\\\\"nginx-deployment\\\\\\\",\\\\\\\"namespace\\\\\\\":\\\\\\\"default\\\\\\\"},\\\\\\\"spec\\\\\\\":{\\\\\\\"replicas\\\\\\\":1,\\\\\\\"selector\\\\\\\":{\\\\\\\"matchLabels\\\\\\\":{\\\\\\\"app\\\\\\\":\\\\\\\"nginx\\\\\\\"}},\\\\\\\"template\\\\\\\":{\\\\\\\"metadata\\\\\\\":{\\\\\\\"labels\\\\\\\":{\\\\\\\"app\\\\\\\":\\\\\\\"nginx\\\\\\\"}},\\\\\\\"spec\\\\\\\":{\\\\\\\"containers\\\\\\\":[{\\\\\\\"image\\\\\\\":\\\\\\\"nginx:latest\\\\\\\",\\\\\\\"name\\\\\\\":\\\\\\\"nginx\\\\\\\",\\\\\\\"ports\\\\\\\":[{\\\\\\\"containerPort\\\\\\\":80}]}]}}}}\\\\n\\\"},\\\"creationTimestamp\\\":\\\"2019-08-07T09:22:42Z\\\",\\\"generation\\\":1,\\\"name\\\":\\\"nginx-deployment\\\",\\\"namespace\\\":\\\"default\\\",\\\"resourceVersion\\\":\\\"237215\\\",\\\"selfLink\\\":\\\"/apis/apps/v1beta1/namespaces/default/deployments/nginx-deployment\\\",\\\"uid\\\":\\\"e4e0007a-746b-4235-86cb-86bc3e5d831f\\\"},\\\"spec\\\":{\\\"progressDeadlineSeconds\\\":600,\\\"replicas\\\":1,\\\"revisionHistoryLimit\\\":10,\\\"selector\\\":{\\\"matchLabels\\\":{\\\"app\\\":\\\"nginx\\\"}},\\\"strategy\\\":{\\\"rollingUpdate\\\":{\\\"maxSurge\\\":\\\"25%\\\",\\\"maxUnavailable\\\":\\\"25%\\\"},\\\"type\\\":\\\"RollingUpdate\\\"},\\\"template\\\":{\\\"metadata\\\":{\\\"annotations\\\":{\\\"caGUIDs\\\":\\\"{\\\\\\\"customerGUID\\\\\\\":\\\\\\\"1e3a88bf-92ce-44f8-914e-cbe71830d566\\\\\\\",\\\\\\\"solutionGUID\\\\\\\":\\\\\\\"3efee730-dd34-4f15-9b7e-15a6ecdb2c9b\\\\\\\",\\\\\\\"componentGUID\\\\\\\":\\\\\\\"757e6064-7757-4ec5-bb90-35d268dc45a1\\\\\\\"}\\\"},\\\"creationTimestamp\\\":null,\\\"labels\\\":{\\\"app\\\":\\\"nginx\\\"}},\\\"spec\\\":{\\\"containers\\\":[{\\\"image\\\":\\\"nginx:latest\\\",\\\"imagePullPolicy\\\":\\\"Always\\\",\\\"name\\\":\\\"nginx\\\",\\\"ports\\\":[{\\\"containerPort\\\":80,\\\"protocol\\\":\\\"TCP\\\"}],\\\"resources\\\":{},\\\"terminationMessagePath\\\":\\\"/dev/termination-log\\\",\\\"terminationMessagePolicy\\\":\\\"File\\\"}],\\\"dnsPolicy\\\":\\\"ClusterFirst\\\",\\\"restartPolicy\\\":\\\"Always\\\",\\\"schedulerName\\\":\\\"default-scheduler\\\",\\\"securityContext\\\":{},\\\"terminationGracePeriodSeconds\\\":30}}},\\\"status\\\":{\\\"conditions\\\":[{\\\"lastT"
// 2019/08/07 13:57:36 recv: "ransitionTime\\\":\\\"2019-08-07T09:22:42Z\\\",\\\"lastUpdateTime\\\":\\\"2019-08-07T09:22:42Z\\\",\\\"message\\\":\\\"Created new replica set \\\\\\\"nginx-deployment-68c7f5464c\\\\\\\"\\\",\\\"reason\\\":\\\"NewReplicaSetCreated\\\",\\\"status\\\":\\\"True\\\",\\\"type\\\":\\\"Progressing\\\"},{\\\"lastTransitionTime\\\":\\\"2019-08-07T09:22:42Z\\\",\\\"lastUpdateTime\\\":\\\"2019-08-07T09:22:42Z\\\",\\\"message\\\":\\\"Deployment does not have minimum availability.\\\",\\\"reason\\\":\\\"MinimumReplicasUnavailable\\\",\\\"status\\\":\\\"False\\\",\\\"type\\\":\\\"Available\\\"}],\\\"observedGeneration\\\":1,\\\"unavailableReplicas\\\":1}}\"}}]}"
func MockWebsocketURLData() (webSockerURL WebSocketURL) {
	clusterName := "kubernetes"
	customerGUID := "1e3a88bf-92ce-44f8-914e-cbe71830d566"
	webSockerURL.ForceQuery = true
	webSockerURL.Host = "postman.eudev2.cyberarmorsoft.com"
	webSockerURL.Scheme = "wss"
	webSockerURL.Path = fmt.Sprintf("waitfornotification/%s-%s", customerGUID, clusterName)
	return webSockerURL
}
func TestPostbox(t *testing.T) {
	webSockerURL := MockWebsocketURLData()
	u := url.URL{Scheme: webSockerURL.Scheme, Host: webSockerURL.Host, Path: webSockerURL.Path, ForceQuery: webSockerURL.ForceQuery}
	log.Printf("connecting to %s", u.String())

	_, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Errorf("error: %s", err)
	}
	// t.Errorf("error: %v", conn)

	// fmt.Printf("%v", conn)
}

func TestGetCommands(t *testing.T) {

	webSockerURL := MockWebsocketURLData()
	u := url.URL{Scheme: webSockerURL.Scheme, Host: webSockerURL.Host, Path: webSockerURL.Path, ForceQuery: webSockerURL.ForceQuery}
	log.Printf("connecting to %s", u.String())

	_, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Errorf("error: %s", err)
	}
	// t.Errorf("error: %v", conn)

	// fmt.Printf("%v", conn)
}
