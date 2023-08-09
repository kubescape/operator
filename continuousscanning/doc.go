// package continuousscanning provides utilities that help the Operator watch for changes
// in the cluster it operates in
//
// # Resource Kinds that the Operator is interested in
// 
// The non-namespaced kinds the Operator is interested in are:
// 	- */*/ClusterRole
// 	- */*/ClusterRoleBinding
// 	- rbac.authorization.k8s.io/v1/ClusterRole
// 	- rbac.authorization.k8s.io/v1/ClusterRoleBinding
// 	- /v1/Namespace
// 	- */*/Namespace
// 	- /v1/Node
// 	- admissionregistration.k8s.io/*/MutatingWebhookConfiguration
// 	- admissionregistration.k8s.io/*/ValidatingWebhookConfiguration
// 	- apiregistration.k8s.io/v1/APIService
// 	- policy/*/PodSecurityPolicy
// 
// The Namespaced kinds the Operator is interested in are:
// 	- */*/ConfigMap
// 	- */*/CronJob
// 	- */*/DaemonSet
// 	- */*/Deployment
// 	- */*/Job
// 	- */*/Pod
// 	- */*/ReplicaSet
// 	- */*/Role
// 	- */*/RoleBinding
// 	- */*/ServiceAccount
// 	- */*/StatefulSet
// 	- /v1/Pod
// 	- /v1/Service
// 	- /v1/ServiceAccount
// 	- apps/v1/DaemonSet
// 	- apps/v1/Deployment
// 	- apps/v1/ReplicaSet
// 	- apps/v1/StatefulSet
// 	- batch/*/CronJob
// 	- batch/*/Job
// 	- networking.k8s.io/v1/Ingress
// 	- networking.k8s.io/v1/NetworkPolicy
// 	- rbac.authorization.k8s.io/v1/Role
// 	- rbac.authorization.k8s.io/v1/RoleBinding
package continuousscanning
