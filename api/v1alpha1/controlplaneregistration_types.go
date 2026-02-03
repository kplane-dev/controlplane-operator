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

// ControlPlaneRegistrationService declares a service intent for a control plane.
// +kubebuilder:validation:Enum=Controllers;Scheduler;Workloads
type ControlPlaneRegistrationService string

const (
	ControlPlaneServiceControllers ControlPlaneRegistrationService = "Controllers"
	ControlPlaneServiceScheduler   ControlPlaneRegistrationService = "Scheduler"
	ControlPlaneServiceWorkloads   ControlPlaneRegistrationService = "Workloads"
)

// ControlPlaneRegistrationMode declares the service separation mode.
// +kubebuilder:validation:Enum=Shared;Dedicated
type ControlPlaneRegistrationMode string

const (
	ControlPlaneRegistrationModeShared    ControlPlaneRegistrationMode = "Shared"
	ControlPlaneRegistrationModeDedicated ControlPlaneRegistrationMode = "Dedicated"
)

// ControlPlaneRegistrationSpec defines the desired state of ControlPlaneRegistration.
type ControlPlaneRegistrationSpec struct {
	// controlPlaneRef references the target ControlPlane.
	// +required
	ControlPlaneRef corev1.LocalObjectReference `json:"controlPlaneRef"`

	// endpointRef optionally overrides which ControlPlaneEndpoint to use.
	// +optional
	EndpointRef *ControlPlaneEndpointReference `json:"endpointRef,omitempty"`

	// kubeconfigSecretRef optionally overrides the kubeconfig secret used by consumers.
	// +optional
	KubeconfigSecretRef *corev1.SecretReference `json:"kubeconfigSecretRef,omitempty"`

	// services is the list of service intents for this control plane.
	// +optional
	Services []ControlPlaneRegistrationService `json:"services,omitempty"`

	// mode declares whether services should be shared or dedicated.
	// +optional
	Mode ControlPlaneRegistrationMode `json:"mode,omitempty"`
}

// ControlPlaneRegistrationStatus defines the observed state of ControlPlaneRegistration.
type ControlPlaneRegistrationStatus struct {
	// ready indicates whether the registration has a resolved endpoint and kubeconfig.
	// +optional
	Ready bool `json:"ready,omitempty"`

	// resolvedEndpoint is the endpoint chosen after reference resolution.
	// +optional
	ResolvedEndpoint string `json:"resolvedEndpoint,omitempty"`

	// resolvedKubeconfigSecretRef is the final secret reference used by consumers.
	// +optional
	ResolvedKubeconfigSecretRef *corev1.SecretReference `json:"resolvedKubeconfigSecretRef,omitempty"`

	// observedGeneration reflects the generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the registration.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.status.resolvedEndpoint`,priority=1
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.ready`

// ControlPlaneRegistration is the Schema for the controlplaneregistrations API.
type ControlPlaneRegistration struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of ControlPlaneRegistration.
	// +required
	Spec ControlPlaneRegistrationSpec `json:"spec"`

	// status defines the observed state of ControlPlaneRegistration.
	// +optional
	Status ControlPlaneRegistrationStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// ControlPlaneRegistrationList contains a list of ControlPlaneRegistration.
type ControlPlaneRegistrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ControlPlaneRegistration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ControlPlaneRegistration{}, &ControlPlaneRegistrationList{})
}
