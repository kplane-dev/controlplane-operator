/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ControlPlaneMode declares the type of control plane.
// +kubebuilder:validation:Enum=Virtual;Dedicated
type ControlPlaneMode string

const (
	ControlPlaneModeVirtual   ControlPlaneMode = "Virtual"
	ControlPlaneModeDedicated ControlPlaneMode = "Dedicated"
)

// ControlPlaneSpec defines the desired state of ControlPlane.
type ControlPlaneSpec struct {
	// classRef is the ControlPlaneClass used to apply defaults and policy.
	// +optional
	ClassRef *corev1.LocalObjectReference `json:"classRef,omitempty"`

	// mode selects the control plane type. Virtual is the default for v0/v1.
	// +kubebuilder:default=Virtual
	// +optional
	Mode ControlPlaneMode `json:"mode,omitempty"`

	// endpointRef references a ControlPlaneEndpoint that provides the API endpoint.
	// +optional
	EndpointRef *ControlPlaneEndpointReference `json:"endpointRef,omitempty"`

	// virtual configures virtual control planes served by the shared apiserver.
	// +optional
	Virtual *VirtualControlPlaneSpec `json:"virtual,omitempty"`

	// dedicated configures future provider-backed control planes.
	// +optional
	Dedicated *DedicatedControlPlaneSpec `json:"dedicated,omitempty"`
}

// ControlPlaneEndpointReference references a ControlPlaneEndpoint resource.
type ControlPlaneEndpointReference struct {
	// name is the name of the ControlPlaneEndpoint.
	// +required
	Name string `json:"name"`
}

// VirtualControlPlaneSpec configures a virtual control plane instance.
type VirtualControlPlaneSpec struct {
	// clusterPath is the path segment used in /clusters/<clusterPath>/control-plane.
	// Defaults to the ControlPlane name.
	// +kubebuilder:validation:Pattern=^[a-z0-9]([-a-z0-9]*[a-z0-9])?$
	// +kubebuilder:validation:MaxLength=63
	// +optional
	ClusterPath string `json:"clusterPath,omitempty"`
}

// DedicatedControlPlaneSpec configures provider-backed control planes (future).
type DedicatedControlPlaneSpec struct {
	// providerRef references a provider implementation for the control plane.
	// +optional
	ProviderRef *corev1.TypedLocalObjectReference `json:"providerRef,omitempty"`

	// parametersRef references provider-specific parameters.
	// +optional
	ParametersRef *corev1.TypedLocalObjectReference `json:"parametersRef,omitempty"`
}

// ControlPlaneStatus defines the observed state of ControlPlane.
type ControlPlaneStatus struct {
	// endpoint is the API endpoint for this control plane.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// kubeconfigSecretRef points to the management-plane Secret containing kubeconfig.
	// +optional
	KubeconfigSecretRef *corev1.SecretReference `json:"kubeconfigSecretRef,omitempty"`

	// observedGeneration reflects the generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the ControlPlane resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.status.endpoint`,priority=1
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`

// ControlPlane is the Schema for the controlplanes API
type ControlPlane struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of ControlPlane
	// +required
	Spec ControlPlaneSpec `json:"spec"`

	// status defines the observed state of ControlPlane
	// +optional
	Status ControlPlaneStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// ControlPlaneList contains a list of ControlPlane
type ControlPlaneList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ControlPlane `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ControlPlane{}, &ControlPlaneList{})
}
