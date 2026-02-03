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

package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	controlplanev1alpha1 "github.com/kplane-dev/controlplane-operator/api/v1alpha1"
)

// ControlPlaneRegistrationReconciler reconciles a ControlPlaneRegistration object.
type ControlPlaneRegistrationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=controlplane.kplane.dev,resources=controlplaneregistrations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=controlplane.kplane.dev,resources=controlplaneregistrations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=controlplane.kplane.dev,resources=controlplaneregistrations/finalizers,verbs=update
// +kubebuilder:rbac:groups=controlplane.kplane.dev,resources=controlplanes,verbs=get;list;watch
// +kubebuilder:rbac:groups=controlplane.kplane.dev,resources=controlplaneendpoints,verbs=get;list;watch

func (r *ControlPlaneRegistrationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var registration controlplanev1alpha1.ControlPlaneRegistration
	if err := r.Get(ctx, req.NamespacedName, &registration); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if registration.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}

	if registration.Spec.ControlPlaneRef.Name == "" {
		return r.updateStatus(ctx, &registration, "", nil, conditionRegistrationReady(
			metav1.ConditionFalse,
			"ControlPlaneRefMissing",
			"spec.controlPlaneRef.name is required",
		))
	}

	var controlPlane controlplanev1alpha1.ControlPlane
	if err := r.Get(ctx, client.ObjectKey{Name: registration.Spec.ControlPlaneRef.Name}, &controlPlane); err != nil {
		if apierrors.IsNotFound(err) {
			return r.updateStatus(ctx, &registration, "", nil, conditionRegistrationReady(
				metav1.ConditionFalse,
				"ControlPlaneNotFound",
				fmt.Sprintf("ControlPlane %q not found", registration.Spec.ControlPlaneRef.Name),
			))
		}
		return ctrl.Result{}, err
	}

	endpoint, err := r.resolveRegistrationEndpoint(ctx, &registration, &controlPlane)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("registration endpoint not ready", "reason", err.Error())
			return r.updateStatus(ctx, &registration, "", nil, conditionRegistrationReady(
				metav1.ConditionFalse,
				"EndpointPending",
				err.Error(),
			))
		}
		return ctrl.Result{}, err
	}

	secretRef := registration.Spec.KubeconfigSecretRef
	if secretRef == nil {
		secretRef = controlPlane.Status.KubeconfigSecretRef
	}
	if secretRef == nil || secretRef.Name == "" {
		return r.updateStatus(ctx, &registration, endpoint, nil, conditionRegistrationReady(
			metav1.ConditionFalse,
			"KubeconfigPending",
			"control plane kubeconfig secret is not yet available",
		))
	}

	ready := conditionRegistrationReady(metav1.ConditionTrue, "Resolved", "registration resolved")
	return r.updateStatus(ctx, &registration, endpoint, secretRef, ready)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ControlPlaneRegistrationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&controlplanev1alpha1.ControlPlaneRegistration{}).
		WithOptions(controller.Options{}).
		Named("controlplaneregistration").
		Complete(r)
}

func (r *ControlPlaneRegistrationReconciler) resolveRegistrationEndpoint(
	ctx context.Context,
	registration *controlplanev1alpha1.ControlPlaneRegistration,
	controlPlane *controlplanev1alpha1.ControlPlane,
) (string, error) {
	if registration.Spec.EndpointRef != nil && registration.Spec.EndpointRef.Name != "" {
		return r.resolveEndpointByName(ctx, registration.Spec.EndpointRef.Name)
	}
	if controlPlane.Status.Endpoint != "" {
		return controlPlane.Status.Endpoint, nil
	}
	if controlPlane.Spec.EndpointRef != nil && controlPlane.Spec.EndpointRef.Name != "" {
		return r.resolveEndpointByName(ctx, controlPlane.Spec.EndpointRef.Name)
	}
	return "", apierrors.NewNotFound(schema.GroupResource{
		Group:    controlplanev1alpha1.GroupVersion.Group,
		Resource: "controlplaneendpoints",
	}, "endpoint not yet resolved")
}

func (r *ControlPlaneRegistrationReconciler) resolveEndpointByName(ctx context.Context, name string) (string, error) {
	var endpoint controlplanev1alpha1.ControlPlaneEndpoint
	if err := r.Get(ctx, client.ObjectKey{Name: name}, &endpoint); err != nil {
		return "", err
	}
	if endpoint.Status.ExternalEndpoint != "" {
		return endpoint.Status.ExternalEndpoint, nil
	}
	if endpoint.Spec.ExternalEndpoint != "" {
		return endpoint.Spec.ExternalEndpoint, nil
	}
	if endpoint.Status.Endpoint != "" {
		return endpoint.Status.Endpoint, nil
	}
	if endpoint.Spec.Endpoint != "" {
		return endpoint.Spec.Endpoint, nil
	}
	return "", apierrors.NewNotFound(schema.GroupResource{
		Group:    controlplanev1alpha1.GroupVersion.Group,
		Resource: "controlplaneendpoints",
	}, fmt.Sprintf("endpoint %q is empty", name))
}

func (r *ControlPlaneRegistrationReconciler) updateStatus(
	ctx context.Context,
	registration *controlplanev1alpha1.ControlPlaneRegistration,
	endpoint string,
	secretRef *corev1.SecretReference,
	condition metav1.Condition,
) (ctrl.Result, error) {
	patch := client.MergeFrom(registration.DeepCopy())
	registration.Status.ResolvedEndpoint = endpoint
	registration.Status.ResolvedKubeconfigSecretRef = secretRef
	registration.Status.ObservedGeneration = registration.Generation
	registration.Status.Ready = condition.Status == metav1.ConditionTrue
	condition.ObservedGeneration = registration.Generation
	meta.SetStatusCondition(&registration.Status.Conditions, condition)
	if err := r.Status().Patch(ctx, registration, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func conditionRegistrationReady(status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: 0,
		LastTransitionTime: metav1.Now(),
	}
}
