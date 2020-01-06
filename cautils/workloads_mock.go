package cautils

import (
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// WordpressDeploymentMock -
func WordpressDeploymentMock() []byte {
	w := `{
		"kind": "Deployment",
		"apiVersion": "apps/v1",
		"metadata": {
			"name": "wordpress",
			"namespace": "default",
			"creationTimestamp": null,
			"labels": {
				"app": "wordpress"
			},
			"annotations": {
				"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",\"metadata\":{\"annotations\":{},\"labels\":{\"app\":\"wordpress\"},\"name\":\"wordpress\",\"namespace\":\"default\"},\"spec\":{\"replicas\":1,\"selector\":{\"matchLabels\":{\"app\":\"wordpress\"}},\"template\":{\"metadata\":{\"labels\":{\"app\":\"wordpress\"}},\"spec\":{\"containers\":[{\"env\":[{\"name\":\"WORDPRESS_DB_HOST\",\"value\":\"127.0.0.1\"},{\"name\":\"WORDPRESS_DB_PASSWORD\",\"value\":\"123456\"},{\"name\":\"CAA_LOADNAMES\",\"value\":\"mysqld;apache2\"}],\"image\":\"wordpress:4.8-apache\",\"name\":\"wordpress\",\"ports\":[{\"containerPort\":80,\"name\":\"wordpress\"}]},{\"env\":[{\"name\":\"MYSQL_ROOT_PASSWORD\",\"value\":\"123456\"},{\"name\":\"CAA_LOADNAMES\",\"value\":\"mysqld;apache2\"}],\"image\":\"mysql:5.6\",\"name\":\"mysql\",\"ports\":[{\"containerPort\":3306,\"name\":\"mysql\"}]}]}}}}\n"
			}
		},
		"spec": {
			"replicas": 1,
			"selector": {
				"matchLabels": {
					"app": "wordpress"
				}
			},
			"template": {
				"metadata": {
					"creationTimestamp": null,
					"labels": {
						"app": "wordpress"
					}
				},
				"spec": {
					"containers": [
						{
							"name": "wordpress",
							"image": "wordpress:4.8-apache",
							"ports": [
								{
									"name": "wordpress",
									"containerPort": 80,
									"protocol": "TCP"
								}
							],
							"env": [
								{
									"name": "WORDPRESS_DB_HOST",
									"value": "127.0.0.1"
								},
								{
									"name": "WORDPRESS_DB_PASSWORD",
									"value": "123456"
								},
								{
									"name": "CAA_LOADNAMES",
									"value": "mysqld;apache2"
								}
							],
							"resources": {},
							"terminationMessagePath": "/dev/termination-log",
							"terminationMessagePolicy": "File",
							"imagePullPolicy": "IfNotPresent"
						},
						{
							"name": "mysql",
							"image": "mysql:5.6",
							"ports": [
								{
									"name": "mysql",
									"containerPort": 3306,
									"protocol": "TCP"
								}
							],
							"env": [
								{
									"name": "MYSQL_ROOT_PASSWORD",
									"value": "123456"
								},
								{
									"name": "CAA_LOADNAMES",
									"value": "mysqld;apache2"
								}
							],
							"resources": {},
							"terminationMessagePath": "/dev/termination-log",
							"terminationMessagePolicy": "File",
							"imagePullPolicy": "IfNotPresent"
						}
					],
					"imagePullSecrets": [
						{
							"name": "caregcred"
						}
					],
					"restartPolicy": "Always",
					"terminationGracePeriodSeconds": 30,
					"dnsPolicy": "ClusterFirst",
					"securityContext": {},
					"schedulerName": "default-scheduler"
				}
			},
			"strategy": {
				"type": "RollingUpdate",
				"rollingUpdate": {
					"maxUnavailable": "25%",
					"maxSurge": "25%"
				}
			},
			"revisionHistoryLimit": 10,
			"progressDeadlineSeconds": 600
		}
	}`
	return []byte(w)
}

// Secret -
func SecretMock() []byte {
	s := `{
		"apiVersion": "v1",
		"data": {
			".dockerconfigjson": "eyJhdXRocyI6eyJkcmVnLmV1c3QwLmN5YmVyYXJtb3Jzb2Z0LmNvbTo0NDMiOnsidXNlcm5hbWUiOiJjYXVzZXIiLCJwYXNzd29yZCI6ImpZMzVzbzlnIiwiZW1haWwiOiJiaGlyc2NoYkBjeWJlcmFybW9yLmlvIiwiYXV0aCI6IlkyRjFjMlZ5T21wWk16VnpiemxuIn19fQ=="
		},
		"kind": "Secret",
		"metadata": {
			"annotations": {
				"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"data\":{\".dockerconfigjson\":\"eyJhdXRocyI6eyJkcmVnLmV1c3QwLmN5YmVyYXJtb3Jzb2Z0LmNvbTo0NDMiOnsidXNlcm5hbWUiOiJjYXVzZXIiLCJwYXNzd29yZCI6ImpZMzVzbzlnIiwiZW1haWwiOiJiaGlyc2NoYkBjeWJlcmFybW9yLmlvIiwiYXV0aCI6IlkyRjFjMlZ5T21wWk16VnpiemxuIn19fQ==\"},\"kind\":\"Secret\",\"metadata\":{\"annotations\":{},\"name\":\"caregcred\",\"namespace\":\"cyberarmor-system\",\"selfLink\":\"/api/v1/namespaces/cyberarmor-system/secrets/caregcred\"},\"type\":\"kubernetes.io/dockerconfigjson\"}\n"
			},
			"creationTimestamp": "2020-01-06T07:29:50Z",
			"name": "caregcred",
			"namespace": "cyberarmor-system",
			"resourceVersion": "22044",
			"selfLink": "/api/v1/namespaces/cyberarmor-system/secrets/caregcred",
			"uid": "b78ec77f-6c21-43d2-8d1a-600f29981945"
		},
		"type": "kubernetes.io/dockerconfigjson"
	}`
	return []byte(s)

}

// GetWordpressDeployment -
func GetWordpressDeployment() *appsv1.Deployment {
	dep := &appsv1.Deployment{}
	if err := json.Unmarshal(WordpressDeploymentMock(), dep); err != nil {
		fmt.Println(err)
		return dep
	}
	return dep
}

// GetSecret -
func GetSecret() *corev1.Secret {
	sec := &corev1.Secret{}
	if err := json.Unmarshal(SecretMock(), sec); err != nil {
		fmt.Println(err)
		return sec
	}
	return sec
}
