package main

import (
	"encoding/json"
	"os"
	"testing"
)

var (
	// SIGNERCOMMAND = `{"commands": [{"commandName": "sign","responseID": "12345t","args": {"json": "{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",\"metadata\":{\"annotations\":{\"deployment.kubernetes.io/revision\":\"2\",\"kubectl.kubernetes.io/last-applied-configuration\":\"{\\\"apiVersion\\\":\\\"apps/v1\\\",\\\"kind\\\":\\\"Deployment\\\",\\\"metadata\\\":{\\\"annotations\\\":{},\\\"name\\\":\\\"mysql\\\",\\\"namespace\\\":\\\"default\\\"},\\\"spec\\\":{\\\"selector\\\":{\\\"matchLabels\\\":{\\\"app\\\":\\\"mysql\\\"}},\\\"strategy\\\":{\\\"type\\\":\\\"Recreate\\\"},\\\"template\\\":{\\\"metadata\\\":{\\\"labels\\\":{\\\"app\\\":\\\"mysql\\\"}},\\\"spec\\\":{\\\"containers\\\":[{\\\"env\\\":[{\\\"name\\\":\\\"MYSQL_ROOT_PASSWORD\\\",\\\"value\\\":\\\"password\\\"}],\\\"image\\\":\\\"mysql:5.6\\\",\\\"name\\\":\\\"mysql\\\",\\\"ports\\\":[{\\\"containerPort\\\":3306,\\\"name\\\":\\\"mysql\\\"}],\\\"volumeMounts\\\":[{\\\"mountPath\\\":\\\"/var/lib/mysql\\\",\\\"name\\\":\\\"mysql-persistent-storage\\\"}]}],\\\"volumes\\\":[{\\\"name\\\":\\\"mysql-persistent-storage\\\",\\\"persistentVolumeClaim\\\":{\\\"claimName\\\":\\\"mysql-pv-claim\\\"}}]}}}}\\n\"},\"creationTimestamp\":\"2019-08-14T09:39:07Z\",\"generation\":2,\"name\":\"mysql\",\"namespace\":\"default\",\"resourceVersion\":\"22667\",\"selfLink\":\"/apis/apps/v1beta1/namespaces/default/deployments/mysql\",\"uid\":\"0e102ef1-10dd-4053-b0ef-e7bc2666f4d8\"},\"spec\":{\"progressDeadlineSeconds\":600,\"replicas\":1,\"revisionHistoryLimit\":10,\"selector\":{\"matchLabels\":{\"app\":\"mysql\"}},\"strategy\":{\"type\":\"Recreate\"},\"template\":{\"metadata\":{\"annotations\":{\"caGUIDs\":\"{\\\"customerGUID\\\":\\\"1e3a88bf-92ce-44f8-914e-cbe71830d566\\\",\\\"solutionGUID\\\":\\\"c311cda6-80c4-43b4-85f2-9ef0db6f660c\\\",\\\"componentGUID\\\":\\\"647c191e-fd83-4dbb-813e-54ed9f550a6b\\\",\\\"containers\\\":[{\\\"containerName\\\":\\\"mysql\\\",\\\"processes\\\":[{\\\"name\\\":\\\"mysqld\\\",\\\"componentGUID\\\":\\\"d0bc9aa7-34b6-4935-9ded-2f45f20279a7\\\"}]}]}\",\"last-update\":\"14-08-2019 09:39:59\"},\"creationTimestamp\":null,\"labels\":{\"app\":\"mysql\"}},\"spec\":{\"containers\":[{\"env\":[{\"name\":\"MYSQL_ROOT_PASSWORD\",\"value\":\"password\"}],\"image\":\"mysql:5.6\",\"imagePullPolicy\":\"IfNotPresent\",\"name\":\"mysql\",\"ports\":[{\"containerPort\":3306,\"name\":\"mysql\",\"protocol\":\"TCP\"}],\"resources\":{},\"terminationMessagePath\":\"/dev/termination-log\",\"terminationMessagePolicy\":\"File\",\"volumeMounts\":[{\"mountPath\":\"/var/lib/mysql\",\"name\":\"mysql-persistent-storage\"}]}],\"dnsPolicy\":\"ClusterFirst\",\"restartPolicy\":\"Always\",\"schedulerName\":\"default-scheduler\",\"securityContext\":{},\"terminationGracePeriodSeconds\":30,\"volumes\":[{\"name\":\"mysql-persistent-storage\",\"persistentVolumeClaim\":{\"claimName\":\"mysql-pv-claim\"}}]}}},\"status\":{\"availableReplicas\":1,\"conditions\":[{\"lastTransitionTime\":\"2019-08-14T09:39:07Z\",\"lastUpdateTime\":\"2019-08-14T09:40:19Z\",\"message\":\"ReplicaSet \\\"mysql-576fffb6b9\\\" has successfully progressed.\",\"reason\":\"NewReplicaSetAvailable\",\"status\":\"True\",\"type\":\"Progressing\"},{\"lastTransitionTime\":\"2019-08-14T19:26:19Z\",\"lastUpdateTime\":\"2019-08-14T19:26:19Z\",\"message\":\"Deployment has minimum availability.\",\"reason\":\"MinimumReplicasAvailable\",\"status\":\"True\",\"type\":\"Available\"}],\"observedGeneration\":2,\"readyReplicas\":1,\"replicas\":1,\"updatedReplicas\":1}}","signingProfiles": {"mysql": {"mysqld": {"component": "1e3a88bf92ce44f8914ecbe71830d566/c311cda680c443b485f29ef0db6f660c/d0bc9aa734b649359ded2f45f20279a7","url": "","platform": 0,"architecture": 0,"componentType": 0,"signatureMismatchAction": 0,"executablesList": {"filter": {"includePaths": ["/usr/sbin/","/lib/x86_64-linux-gnu/","/usr/lib/x86_64-linux-gnu/","/etc/cyberarmor/"],"includeExtensions": null},"mainProcess": "mysqld","modulesInfo": [{"name": "mysqld","mandatory": 1,"version": "","signatureMismatchAction": 1,"type": 1}]},"containerName": "mysql","dockerImageTag": "mysql:5.6","dockerImageSHA256": "e2388e706b4e90b2f558126f98eda5b38fc36c9d220468a10535778e28707e2f"}}}}}]}`
	SIGNERCOMMAND = Commands{
		Commands: []Command{
			Command{
				CommandName: "sign",
				ResponseID:  "12345t",
				Args: map[string]interface{}{
					"json": "{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",\"metadata\":{\"annotations\":{\"deployment.kubernetes.io/revision\":\"2\",\"kubectl.kubernetes.io/last-applied-configuration\":\"{\\\"apiVersion\\\":\\\"apps/v1\\\",\\\"kind\\\":\\\"Deployment\\\",\\\"metadata\\\":{\\\"annotations\\\":{},\\\"name\\\":\\\"mysql\\\",\\\"namespace\\\":\\\"default\\\"},\\\"spec\\\":{\\\"selector\\\":{\\\"matchLabels\\\":{\\\"app\\\":\\\"mysql\\\"}},\\\"strategy\\\":{\\\"type\\\":\\\"Recreate\\\"},\\\"template\\\":{\\\"metadata\\\":{\\\"labels\\\":{\\\"app\\\":\\\"mysql\\\"}},\\\"spec\\\":{\\\"containers\\\":[{\\\"env\\\":[{\\\"name\\\":\\\"MYSQL_ROOT_PASSWORD\\\",\\\"value\\\":\\\"password\\\"}],\\\"image\\\":\\\"mysql:5.6\\\",\\\"name\\\":\\\"mysql\\\",\\\"ports\\\":[{\\\"containerPort\\\":3306,\\\"name\\\":\\\"mysql\\\"}],\\\"volumeMounts\\\":[{\\\"mountPath\\\":\\\"/var/lib/mysql\\\",\\\"name\\\":\\\"mysql-persistent-storage\\\"}]}],\\\"volumes\\\":[{\\\"name\\\":\\\"mysql-persistent-storage\\\",\\\"persistentVolumeClaim\\\":{\\\"claimName\\\":\\\"mysql-pv-claim\\\"}}]}}}}\\n\"},\"creationTimestamp\":\"2019-08-14T09:39:07Z\",\"generation\":2,\"name\":\"mysql\",\"namespace\":\"default\",\"resourceVersion\":\"22667\",\"selfLink\":\"/apis/apps/v1beta1/namespaces/default/deployments/mysql\",\"uid\":\"0e102ef1-10dd-4053-b0ef-e7bc2666f4d8\"},\"spec\":{\"progressDeadlineSeconds\":600,\"replicas\":1,\"revisionHistoryLimit\":10,\"selector\":{\"matchLabels\":{\"app\":\"mysql\"}},\"strategy\":{\"type\":\"Recreate\"},\"template\":{\"metadata\":{\"annotations\":{\"caGUIDs\":\"{\\\"customerGUID\\\":\\\"1e3a88bf-92ce-44f8-914e-cbe71830d566\\\",\\\"solutionGUID\\\":\\\"c311cda6-80c4-43b4-85f2-9ef0db6f660c\\\",\\\"componentGUID\\\":\\\"647c191e-fd83-4dbb-813e-54ed9f550a6b\\\",\\\"containers\\\":[{\\\"containerName\\\":\\\"mysql\\\",\\\"processes\\\":[{\\\"name\\\":\\\"mysqld\\\",\\\"componentGUID\\\":\\\"d0bc9aa7-34b6-4935-9ded-2f45f20279a7\\\"}]}]}\",\"last-update\":\"14-08-2019 09:39:59\"},\"creationTimestamp\":null,\"labels\":{\"app\":\"mysql\"}},\"spec\":{\"containers\":[{\"env\":[{\"name\":\"MYSQL_ROOT_PASSWORD\",\"value\":\"password\"}],\"image\":\"mysql:5.6\",\"imagePullPolicy\":\"IfNotPresent\",\"name\":\"mysql\",\"ports\":[{\"containerPort\":3306,\"name\":\"mysql\",\"protocol\":\"TCP\"}],\"resources\":{},\"terminationMessagePath\":\"/dev/termination-log\",\"terminationMessagePolicy\":\"File\",\"volumeMounts\":[{\"mountPath\":\"/var/lib/mysql\",\"name\":\"mysql-persistent-storage\"}]}],\"dnsPolicy\":\"ClusterFirst\",\"restartPolicy\":\"Always\",\"schedulerName\":\"default-scheduler\",\"securityContext\":{},\"terminationGracePeriodSeconds\":30,\"volumes\":[{\"name\":\"mysql-persistent-storage\",\"persistentVolumeClaim\":{\"claimName\":\"mysql-pv-claim\"}}]}}},\"status\":{\"availableReplicas\":1,\"conditions\":[{\"lastTransitionTime\":\"2019-08-14T09:39:07Z\",\"lastUpdateTime\":\"2019-08-14T09:40:19Z\",\"message\":\"ReplicaSet \\\"mysql-576fffb6b9\\\" has successfully progressed.\",\"reason\":\"NewReplicaSetAvailable\",\"status\":\"True\",\"type\":\"Progressing\"},{\"lastTransitionTime\":\"2019-08-14T19:26:19Z\",\"lastUpdateTime\":\"2019-08-14T19:26:19Z\",\"message\":\"Deployment has minimum availability.\",\"reason\":\"MinimumReplicasAvailable\",\"status\":\"True\",\"type\":\"Available\"}],\"observedGeneration\":2,\"readyReplicas\":1,\"replicas\":1,\"updatedReplicas\":1}}",
					"signingProfiles": map[string]interface{}{
						"mysql": map[string]interface{}{
							"mysqld": Envelope{
								Component:               "1e3a88bf92ce44f8914ecbe71830d566/6a16b37add554b4391fee87b7c296aae/17601a7e2d284b6a919366f06e5ad5d3",
								URL:                     "https://sigs.eudev2.cyberarmorsoft.com/signzip",
								Platform:                10,
								Architecture:            2,
								ComponentType:           1,
								SignatureMismatchAction: 11,
								ExecutablesList: []ExecutablesList{
									ExecutablesList{
										Filter: Filter{
											IncludePaths: []string{
												"/usr/sbin/",
												"/lib/x86_64-linux-gnu/",
												"/usr/lib/x86_64-linux-gnu/",
												"/etc/cyberarmor/",
											},
											IncludeExtensions: []string{},
										},
										MainProcess: "mysqld",
										ModulesInfo: []ModulesInfo{
											ModulesInfo{
												Name:                    "mysqld",
												Mandatory:               1,
												Version:                 "1.0.0",
												SignatureMismatchAction: 1,
												Type:                    1,
											},
										},
									},
								},
								ContainerName:     "mysql",
								DockerImageTag:    "mysql:5.6",
								DockerImageSHA256: "e2388e706b4e90b2f558126f98eda5b38fc36c9d220468a10535778e28707e2f",
							},
						},
					},
				},
			},
		},
	}
)

func TestHandlePostmanRequest(t *testing.T) {
	if d := os.Getenv("WEBSOCKETDEBUG"); d == "" {
		return
	}
	websocketHandler := CreateWebSocketHandler()
	signerCommand, err := json.Marshal(SIGNERCOMMAND)
	if err != nil {
		t.Error(err)
	}
	if errs := websocketHandler.HandlePostmanRequest(signerCommand); len(errs) != 0 {
		for _, i := range errs {
			t.Errorf("%v", i)
		}

	}

}
