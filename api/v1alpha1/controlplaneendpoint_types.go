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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ControlPlaneEndpointSpec defines the desired endpoint for a control plane.
type ControlPlaneEndpointSpec struct {
	// endpoint is the desired API endpoint for this control plane.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`
}

// ControlPlaneEndpointStatus defines the observed endpoint for a control plane.
type ControlPlaneEndpointStatus struct {
	// endpoint is the observed API endpoint for this control plane.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// conditions represent the current state of the endpoint.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.status.endpoint`,priority=1

// ControlPlaneEndpoint is the Schema for the controlplaneendpoints API.
type ControlPlaneEndpoint struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired endpoint
	// +required
	Spec ControlPlaneEndpointSpec `json:"spec"`

	// status defines the observed endpoint
	// +optional
	Status ControlPlaneEndpointStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// ControlPlaneEndpointList contains a list of ControlPlaneEndpoint.
type ControlPlaneEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ControlPlaneEndpoint `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ControlPlaneEndpoint{}, &ControlPlaneEndpointList{})
}
