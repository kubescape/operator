#! /usr/bin/env python3

gvks = [
    ['/v1/Pod', '/v1/ServiceAccount', 'apps/v1/DaemonSet', 'apps/v1/Deployment', 'apps/v1/ReplicaSet', 'apps/v1/StatefulSet', 'batch/*/CronJob', 'batch/*/Job', 'rbac.authorization.k8s.io/v1/ClusterRole', 'rbac.authorization.k8s.io/v1/ClusterRoleBinding', 'rbac.authorization.k8s.io/v1/Role', 'rbac.authorization.k8s.io/v1/RoleBinding'],
    ['/v1/Service', 'apiregistration.k8s.io/v1/APIService'],
    ['/v1/Namespace', 'networking.k8s.io/v1/NetworkPolicy'],
    ['/v1/Node', '/v1/Pod', 'apps/v1/DaemonSet', 'apps/v1/Deployment', 'apps/v1/ReplicaSet', 'apps/v1/StatefulSet', 'batch/*/CronJob', 'batch/*/Job'],
    ['*/*/ClusterRole', '*/*/ClusterRoleBinding', '*/*/Role'],
    ['/v1/Service', 'networking.k8s.io/v1/Ingress'],
    ['/v1/Pod', '/v1/ServiceAccount', 'apps/v1/DaemonSet', 'apps/v1/Deployment', 'apps/v1/ReplicaSet', 'apps/v1/StatefulSet', 'batch/*/CronJob', 'batch/*/Job'],
    ['/v1/Pod', 'apps/v1/DaemonSet', 'apps/v1/Deployment', 'apps/v1/ReplicaSet', 'apps/v1/StatefulSet', 'batch/*/CronJob', 'batch/*/Job', 'networking.k8s.io/v1/NetworkPolicy'],
    ['*/*/Namespace', '*/*/ServiceAccount'],
    ['*/*/ClusterRole', '*/*/ClusterRoleBinding', '*/*/ConfigMap', '*/*/Role', '*/*/RoleBinding'],
    ['*/*/ConfigMap', '*/*/Deployment'],
    ['/v1/Pod', 'apps/v1/DaemonSet', 'apps/v1/Deployment', 'apps/v1/ReplicaSet', 'apps/v1/StatefulSet', 'batch/*/CronJob', 'batch/*/Job', 'policy/*/PodSecurityPolicy'],
    ['/v1/Namespace', 'admissionregistration.k8s.io/*/MutatingWebhookConfiguration', 'admissionregistration.k8s.io/*/ValidatingWebhookConfiguration'],
    ['rbac.authorization.k8s.io/v1/ClusterRole', 'rbac.authorization.k8s.io/v1/ClusterRoleBinding', 'rbac.authorization.k8s.io/v1/Role', 'rbac.authorization.k8s.io/v1/RoleBinding'],
    ['*/*/CronJob', '*/*/DaemonSet', '*/*/Deployment', '*/*/Job', '*/*/Pod', '*/*/ReplicaSet', '*/*/StatefulSet'],
    ['/v1/Pod', '/v1/Service', 'apps/v1/DaemonSet', 'apps/v1/Deployment', 'apps/v1/ReplicaSet', 'apps/v1/StatefulSet', 'batch/*/CronJob', 'batch/*/Job'],
    ['*/*/ClusterRole', '*/*/ClusterRoleBinding', '*/*/Role', '*/*/RoleBinding'],
    ['/v1/Pod', 'apps/v1/DaemonSet', 'apps/v1/Deployment', 'apps/v1/ReplicaSet', 'apps/v1/StatefulSet', 'batch/*/CronJob', 'batch/*/Job'],
]

unique_gvks: set[str] = set()

for gvk_list in gvks:
    for gvk in gvk_list:
        unique_gvks.add(gvk)

gvks_str = "\n".join(sorted(unique_gvks))
print(f'Unique gvks: \n{gvks_str}')
print(f'Unique gvks count: {len(unique_gvks)}')
