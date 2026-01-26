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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ControlPlaneClassSpec defines the desired state of ControlPlaneClass.
type ControlPlaneClassSpec struct {
	// addons is a list of named addon bundles to apply.
	// +optional
	Addons []string `json:"addons,omitempty"`

	// auth configures default authentication/authorization posture.
	// +optional
	Auth *ControlPlaneClassAuthSpec `json:"auth,omitempty"`

	// modesAllowed restricts which control plane modes can use this class.
	// +optional
	ModesAllowed []ControlPlaneMode `json:"modesAllowed,omitempty"`
}

// ControlPlaneClassAuthSpec provides basic auth defaults (v0/v1).
type ControlPlaneClassAuthSpec struct {
	// model is a small string that can be interpreted by the operator in future.
	// +optional
	Model string `json:"model,omitempty"`

	// defaultRole is applied to bootstrap admin credentials.
	// +optional
	DefaultRole string `json:"defaultRole,omitempty"`
}

// ControlPlaneClassStatus defines the observed state of ControlPlaneClass.
type ControlPlaneClassStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// conditions represent the current state of the ControlPlaneClass resource.
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

// ControlPlaneClass is the Schema for the controlplaneclasses API
type ControlPlaneClass struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of ControlPlaneClass
	// +required
	Spec ControlPlaneClassSpec `json:"spec"`

	// status defines the observed state of ControlPlaneClass
	// +optional
	Status ControlPlaneClassStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// ControlPlaneClassList contains a list of ControlPlaneClass
type ControlPlaneClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ControlPlaneClass `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ControlPlaneClass{}, &ControlPlaneClassList{})
}
