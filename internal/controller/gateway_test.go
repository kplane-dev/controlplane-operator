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
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	controlplanev1alpha1 "github.com/kplane-dev/controlplane-operator/api/v1alpha1"
	"github.com/kplane-dev/controlplane-operator/internal/config"
)

var _ = Describe("Gateway Integration", func() {
	const (
		cpName    = "test-gateway-cp"
		className = "gateway-class"
	)

	ctx := context.Background()

	newReconciler := func() *ControlPlaneReconciler {
		return &ControlPlaneReconciler{
			Client:        k8sClient,
			Scheme:        k8sClient.Scheme(),
			ClusterConfig: &rest.Config{Host: "https://fake-apiserver:6443"},
			Config:        config.DefaultOperatorConfig(),
		}
	}

	Context("renderHostname", func() {
		It("should template the ControlPlane name into the hostname", func() {
			cp := &controlplanev1alpha1.ControlPlane{
				ObjectMeta: metav1.ObjectMeta{Name: "my-cluster"},
			}
			hostname, err := renderHostname("{{.Name}}.clusters.example.com", cp)
			Expect(err).NotTo(HaveOccurred())
			Expect(hostname).To(Equal("my-cluster.clusters.example.com"))
		})

		It("should return error for invalid templates", func() {
			cp := &controlplanev1alpha1.ControlPlane{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
			}
			_, err := renderHostname("{{.Invalid", cp)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("When a ControlPlane has no endpointRef and class has gateway config", func() {
		BeforeEach(func() {
			// Ensure the backend namespace exists for the HTTPRoute.
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kplane-apiserver"}}
			_ = k8sClient.Create(ctx, ns)

			class := &controlplanev1alpha1.ControlPlaneClass{
				ObjectMeta: metav1.ObjectMeta{Name: className},
				Spec: controlplanev1alpha1.ControlPlaneClassSpec{
					Gateway: &controlplanev1alpha1.ControlPlaneClassGatewaySpec{
						ParentRef: controlplanev1alpha1.GatewayParentRef{
							Name:      "test-gateway",
							Namespace: "gateway-ns",
						},
						HostnameTemplate: "{{.Name}}.clusters.test.example.com",
						APIServerRef: &controlplanev1alpha1.GatewayBackendRef{
							Name:      "kplane-apiserver",
							Namespace: "kplane-apiserver",
							Port:      443,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, class)).To(Succeed())

			cp := &controlplanev1alpha1.ControlPlane{
				ObjectMeta: metav1.ObjectMeta{Name: cpName, Namespace: "default"},
				Spec: controlplanev1alpha1.ControlPlaneSpec{
					ClassRef: &corev1.LocalObjectReference{
						Name: className,
					},
				},
			}
			Expect(k8sClient.Create(ctx, cp)).To(Succeed())
		})

		AfterEach(func() {
			cp := &controlplanev1alpha1.ControlPlane{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: cpName, Namespace: "default"}, cp); err == nil {
				cp.Finalizers = nil
				_ = k8sClient.Update(ctx, cp)
				_ = k8sClient.Delete(ctx, cp)
			}

			endpoint := &controlplanev1alpha1.ControlPlaneEndpoint{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: cpName + "-endpoint", Namespace: "default"}, endpoint); err == nil {
				_ = k8sClient.Delete(ctx, endpoint)
			}

			route := &gatewayv1.HTTPRoute{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: cpName + "-route", Namespace: "default"}, route); err == nil {
				_ = k8sClient.Delete(ctx, route)
			}

			class := &controlplanev1alpha1.ControlPlaneClass{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: className}, class); err == nil {
				_ = k8sClient.Delete(ctx, class)
			}
		})

		It("should auto-create ControlPlaneEndpoint and HTTPRoute", func() {
			r := newReconciler()

			// First reconcile — will create gateway resources and set endpointRef.
			// It will then fail on bootstrapVirtualCluster (no real apiserver), which is expected.
			_, _ = r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: cpName, Namespace: "default"},
			})

			// Verify ControlPlaneEndpoint was created.
			endpoint := &controlplanev1alpha1.ControlPlaneEndpoint{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: cpName + "-endpoint", Namespace: "default"}, endpoint)
			Expect(err).NotTo(HaveOccurred())
			Expect(endpoint.Spec.Endpoint).To(ContainSubstring("kplane-apiserver.kplane-apiserver.svc.cluster.local"))
			Expect(endpoint.Spec.Endpoint).To(ContainSubstring("/clusters/" + cpName + "/control-plane"))
			Expect(endpoint.Spec.ExternalEndpoint).To(Equal("https://" + cpName + ".clusters.test.example.com"))

			// Verify owner reference points to the ControlPlane.
			Expect(endpoint.OwnerReferences).To(HaveLen(1))
			Expect(endpoint.OwnerReferences[0].Kind).To(Equal("ControlPlane"))
			Expect(endpoint.OwnerReferences[0].Name).To(Equal(cpName))

			// Verify HTTPRoute was created.
			route := &gatewayv1.HTTPRoute{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: cpName + "-route", Namespace: "default"}, route)
			Expect(err).NotTo(HaveOccurred())
			Expect(route.Spec.Hostnames).To(HaveLen(1))
			Expect(string(route.Spec.Hostnames[0])).To(Equal(cpName + ".clusters.test.example.com"))
			Expect(route.Spec.ParentRefs).To(HaveLen(1))
			Expect(string(route.Spec.ParentRefs[0].Name)).To(Equal("test-gateway"))
			Expect(string(*route.Spec.ParentRefs[0].Namespace)).To(Equal("gateway-ns"))

			// Verify the ControlPlane now has endpointRef set.
			cp := &controlplanev1alpha1.ControlPlane{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: cpName, Namespace: "default"}, cp)
			Expect(err).NotTo(HaveOccurred())
			Expect(cp.Spec.EndpointRef).NotTo(BeNil())
			Expect(cp.Spec.EndpointRef.Name).To(Equal(cpName + "-endpoint"))
		})
	})

	Context("When a ControlPlane has an explicit endpointRef", func() {
		const explicitCPName = "test-explicit-ep"

		BeforeEach(func() {
			class := &controlplanev1alpha1.ControlPlaneClass{
				ObjectMeta: metav1.ObjectMeta{Name: "explicit-class"},
				Spec: controlplanev1alpha1.ControlPlaneClassSpec{
					Gateway: &controlplanev1alpha1.ControlPlaneClassGatewaySpec{
						ParentRef: controlplanev1alpha1.GatewayParentRef{
							Name:      "test-gateway",
							Namespace: "gateway-ns",
						},
						HostnameTemplate: "{{.Name}}.clusters.test.example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, class)).To(Succeed())

			endpoint := &controlplanev1alpha1.ControlPlaneEndpoint{
				ObjectMeta: metav1.ObjectMeta{Name: "manual-endpoint", Namespace: "default"},
				Spec: controlplanev1alpha1.ControlPlaneEndpointSpec{
					Endpoint: "https://manual.example.com:6443",
				},
			}
			Expect(k8sClient.Create(ctx, endpoint)).To(Succeed())

			cp := &controlplanev1alpha1.ControlPlane{
				ObjectMeta: metav1.ObjectMeta{Name: explicitCPName, Namespace: "default"},
				Spec: controlplanev1alpha1.ControlPlaneSpec{
					ClassRef: &corev1.LocalObjectReference{
						Name: "explicit-class",
					},
					EndpointRef: &controlplanev1alpha1.ControlPlaneEndpointReference{
						Name: "manual-endpoint",
					},
				},
			}
			Expect(k8sClient.Create(ctx, cp)).To(Succeed())
		})

		AfterEach(func() {
			cp := &controlplanev1alpha1.ControlPlane{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: explicitCPName, Namespace: "default"}, cp); err == nil {
				cp.Finalizers = nil
				_ = k8sClient.Update(ctx, cp)
				_ = k8sClient.Delete(ctx, cp)
			}

			endpoint := &controlplanev1alpha1.ControlPlaneEndpoint{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "manual-endpoint", Namespace: "default"}, endpoint); err == nil {
				_ = k8sClient.Delete(ctx, endpoint)
			}

			class := &controlplanev1alpha1.ControlPlaneClass{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "explicit-class"}, class); err == nil {
				_ = k8sClient.Delete(ctx, class)
			}
		})

		It("should NOT create gateway resources when endpointRef is set", func() {
			r := newReconciler()

			_, _ = r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: explicitCPName, Namespace: "default"},
			})

			// No auto-created endpoint should exist.
			autoEndpoint := &controlplanev1alpha1.ControlPlaneEndpoint{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: explicitCPName + "-endpoint", Namespace: "default"}, autoEndpoint)
			Expect(err).To(HaveOccurred()) // should be NotFound

			// No HTTPRoute should exist.
			route := &gatewayv1.HTTPRoute{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: explicitCPName + "-route", Namespace: "default"}, route)
			Expect(err).To(HaveOccurred()) // should be NotFound
		})
	})

	Context("When class has no gateway config", func() {
		const noGwCPName = "test-no-gateway"

		BeforeEach(func() {
			class := &controlplanev1alpha1.ControlPlaneClass{
				ObjectMeta: metav1.ObjectMeta{Name: "no-gw-class"},
				Spec:       controlplanev1alpha1.ControlPlaneClassSpec{},
			}
			Expect(k8sClient.Create(ctx, class)).To(Succeed())

			cp := &controlplanev1alpha1.ControlPlane{
				ObjectMeta: metav1.ObjectMeta{Name: noGwCPName, Namespace: "default"},
				Spec: controlplanev1alpha1.ControlPlaneSpec{
					ClassRef: &corev1.LocalObjectReference{
						Name: "no-gw-class",
					},
				},
			}
			Expect(k8sClient.Create(ctx, cp)).To(Succeed())
		})

		AfterEach(func() {
			cp := &controlplanev1alpha1.ControlPlane{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: noGwCPName, Namespace: "default"}, cp); err == nil {
				cp.Finalizers = nil
				_ = k8sClient.Update(ctx, cp)
				_ = k8sClient.Delete(ctx, cp)
			}

			class := &controlplanev1alpha1.ControlPlaneClass{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "no-gw-class"}, class); err == nil {
				_ = k8sClient.Delete(ctx, class)
			}
		})

		It("should NOT create gateway resources", func() {
			r := newReconciler()

			_, _ = r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: noGwCPName, Namespace: "default"},
			})

			autoEndpoint := &controlplanev1alpha1.ControlPlaneEndpoint{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: noGwCPName + "-endpoint", Namespace: "default"}, autoEndpoint)
			Expect(err).To(HaveOccurred())

			route := &gatewayv1.HTTPRoute{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: noGwCPName + "-route", Namespace: "default"}, route)
			Expect(err).To(HaveOccurred())
		})
	})
})
