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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controlplanev1alpha1 "github.com/kplane-dev/controlplane-operator/api/v1alpha1"
)

var _ = Describe("ControlPlaneRegistration Controller", func() {
	const (
		controlPlaneName = "test-cp"
		endpointName     = "test-endpoint"
		registrationName = "test-registration"
	)

	ctx := context.Background()

	AfterEach(func() {
		_ = k8sClient.Delete(ctx, &controlplanev1alpha1.ControlPlaneRegistration{
			ObjectMeta: metav1.ObjectMeta{Name: registrationName},
		})
		_ = k8sClient.Delete(ctx, &controlplanev1alpha1.ControlPlane{
			ObjectMeta: metav1.ObjectMeta{Name: controlPlaneName},
		})
		_ = k8sClient.Delete(ctx, &controlplanev1alpha1.ControlPlaneEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: endpointName},
		})
	})

	It("resolves endpointRef and kubeconfig from ControlPlane status", func() {
		endpoint := &controlplanev1alpha1.ControlPlaneEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: endpointName},
			Spec: controlplanev1alpha1.ControlPlaneEndpointSpec{
				Endpoint:         "https://internal.example",
				ExternalEndpoint: "https://external.example",
			},
		}
		Expect(k8sClient.Create(ctx, endpoint)).To(Succeed())

		controlPlane := &controlplanev1alpha1.ControlPlane{
			ObjectMeta: metav1.ObjectMeta{Name: controlPlaneName},
			Spec: controlplanev1alpha1.ControlPlaneSpec{
				EndpointRef: &controlplanev1alpha1.ControlPlaneEndpointReference{
					Name: endpointName,
				},
			},
		}
		Expect(k8sClient.Create(ctx, controlPlane)).To(Succeed())
		controlPlane.Status.Endpoint = "https://status.example"
		controlPlane.Status.KubeconfigSecretRef = &corev1.SecretReference{
			Name:      "cp-kubeconfig",
			Namespace: "kplane-cp-test",
		}
		Expect(k8sClient.Status().Update(ctx, controlPlane)).To(Succeed())

		registration := &controlplanev1alpha1.ControlPlaneRegistration{
			ObjectMeta: metav1.ObjectMeta{Name: registrationName},
			Spec: controlplanev1alpha1.ControlPlaneRegistrationSpec{
				ControlPlaneRef: corev1.LocalObjectReference{Name: controlPlaneName},
				EndpointRef: &controlplanev1alpha1.ControlPlaneEndpointReference{
					Name: endpointName,
				},
			},
		}
		Expect(k8sClient.Create(ctx, registration)).To(Succeed())

		reconciler := &ControlPlaneRegistrationReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: registrationName},
		})
		Expect(err).NotTo(HaveOccurred())

		var updated controlplanev1alpha1.ControlPlaneRegistration
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: registrationName}, &updated)).To(Succeed())
		Expect(updated.Status.ResolvedEndpoint).To(Equal("https://external.example"))
		Expect(updated.Status.ResolvedKubeconfigSecretRef).NotTo(BeNil())
		Expect(updated.Status.ResolvedKubeconfigSecretRef.Name).To(Equal("cp-kubeconfig"))
		Expect(updated.Status.Ready).To(BeTrue())
	})

	It("falls back to ControlPlane status endpoint when no endpointRef is provided", func() {
		controlPlane := &controlplanev1alpha1.ControlPlane{
			ObjectMeta: metav1.ObjectMeta{Name: controlPlaneName},
		}
		Expect(k8sClient.Create(ctx, controlPlane)).To(Succeed())
		controlPlane.Status.Endpoint = "https://status-only.example"
		controlPlane.Status.KubeconfigSecretRef = &corev1.SecretReference{
			Name:      "cp-kubeconfig",
			Namespace: "kplane-cp-test",
		}
		Expect(k8sClient.Status().Update(ctx, controlPlane)).To(Succeed())

		registration := &controlplanev1alpha1.ControlPlaneRegistration{
			ObjectMeta: metav1.ObjectMeta{Name: registrationName},
			Spec: controlplanev1alpha1.ControlPlaneRegistrationSpec{
				ControlPlaneRef: corev1.LocalObjectReference{Name: controlPlaneName},
			},
		}
		Expect(k8sClient.Create(ctx, registration)).To(Succeed())

		reconciler := &ControlPlaneRegistrationReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: registrationName},
		})
		Expect(err).NotTo(HaveOccurred())

		var updated controlplanev1alpha1.ControlPlaneRegistration
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: registrationName}, &updated)).To(Succeed())
		Expect(updated.Status.ResolvedEndpoint).To(Equal("https://status-only.example"))
		Expect(updated.Status.ResolvedKubeconfigSecretRef).NotTo(BeNil())
		Expect(updated.Status.Ready).To(BeTrue())
	})
})
