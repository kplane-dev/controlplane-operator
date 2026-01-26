package config

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	DefaultClusterPathPrefix          = "/clusters"
	DefaultControlPlaneSegment        = "control-plane"
	DefaultManagementNamespacePrefix  = "kplane-cp-"
	DefaultVirtualAdminNamespace      = "kplane-system"
	DefaultVirtualAdminServiceAccount = "controlplane-admin"
	DefaultVirtualAdminCRBName        = "controlplane-admin"
	DefaultMaxConcurrentReconciles    = 8
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
type OperatorConfig struct {
	metav1.TypeMeta `json:",inline"`

	// clusterPathPrefix is the apiserver path prefix for cluster routing.
	// +optional
	ClusterPathPrefix string `json:"clusterPathPrefix,omitempty"`

	// controlPlaneSegment is the apiserver path segment for control planes.
	// +optional
	ControlPlaneSegment string `json:"controlPlaneSegment,omitempty"`

	// managementNamespacePrefix is the prefix for per-control-plane namespaces.
	// +optional
	ManagementNamespacePrefix string `json:"managementNamespacePrefix,omitempty"`

	// virtualAdminNamespace is the namespace in each virtual control plane for admin credentials.
	// +optional
	VirtualAdminNamespace string `json:"virtualAdminNamespace,omitempty"`

	// virtualAdminServiceAccount is the ServiceAccount name for admin credentials.
	// +optional
	VirtualAdminServiceAccount string `json:"virtualAdminServiceAccount,omitempty"`

	// virtualAdminClusterRoleBinding is the ClusterRoleBinding name for admin credentials.
	// +optional
	VirtualAdminClusterRoleBinding string `json:"virtualAdminClusterRoleBinding,omitempty"`

	// maxConcurrentReconciles controls the number of parallel ControlPlane reconciles.
	// +optional
	MaxConcurrentReconciles int `json:"maxConcurrentReconciles,omitempty"`
}

func init() {
	SchemeBuilder.Register(&OperatorConfig{})
}

func DefaultOperatorConfig() OperatorConfig {
	cfg := OperatorConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: GroupVersion.String(),
			Kind:       "OperatorConfig",
		},
	}
	SetDefaults_OperatorConfig(&cfg)
	return cfg
}

func SetDefaults_OperatorConfig(cfg *OperatorConfig) {
	if cfg.ClusterPathPrefix == "" {
		cfg.ClusterPathPrefix = DefaultClusterPathPrefix
	}
	if cfg.ControlPlaneSegment == "" {
		cfg.ControlPlaneSegment = DefaultControlPlaneSegment
	}
	if cfg.ManagementNamespacePrefix == "" {
		cfg.ManagementNamespacePrefix = DefaultManagementNamespacePrefix
	}
	if cfg.VirtualAdminNamespace == "" {
		cfg.VirtualAdminNamespace = DefaultVirtualAdminNamespace
	}
	if cfg.VirtualAdminServiceAccount == "" {
		cfg.VirtualAdminServiceAccount = DefaultVirtualAdminServiceAccount
	}
	if cfg.VirtualAdminClusterRoleBinding == "" {
		cfg.VirtualAdminClusterRoleBinding = DefaultVirtualAdminCRBName
	}
	if cfg.MaxConcurrentReconciles == 0 {
		cfg.MaxConcurrentReconciles = DefaultMaxConcurrentReconciles
	}
}
