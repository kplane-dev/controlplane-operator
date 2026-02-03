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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	controlplanev1alpha1 "github.com/kplane-dev/controlplane-operator/api/v1alpha1"
	"github.com/kplane-dev/controlplane-operator/internal/config"
)

// ControlPlaneReconciler reconciles a ControlPlane object
type ControlPlaneReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ClusterConfig *rest.Config
	Config        config.OperatorConfig
}

// +kubebuilder:rbac:groups=controlplane.kplane.dev,resources=controlplanes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=controlplane.kplane.dev,resources=controlplanes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=controlplane.kplane.dev,resources=controlplanes/finalizers,verbs=update
// +kubebuilder:rbac:groups=controlplane.kplane.dev,resources=controlplaneclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=controlplane.kplane.dev,resources=controlplaneendpoints,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces;secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ControlPlane object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.1/pkg/reconcile
// nolint:gocyclo
func (r *ControlPlaneReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var controlPlane controlplanev1alpha1.ControlPlane
	if err := r.Get(ctx, req.NamespacedName, &controlPlane); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	mode := controlPlane.Spec.Mode
	if mode == "" {
		mode = controlplanev1alpha1.ControlPlaneModeVirtual
	}

	clusterPath, err := clusterPathForControlPlane(&controlPlane)
	if err != nil {
		log.Error(err, "clusterPath validation failed", "clusterPath", clusterPath)
		return r.updateStatus(ctx, &controlPlane, "", nil, conditionReady(
			metav1.ConditionFalse,
			"InvalidClusterPath",
			err.Error(),
		))
	}

	if controlPlane.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(&controlPlane, controlPlaneFinalizer) {
			if err := r.reconcileDelete(ctx, &controlPlane); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(&controlPlane, controlPlaneFinalizer)
			if err := r.Update(ctx, &controlPlane); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&controlPlane, controlPlaneFinalizer) {
		controllerutil.AddFinalizer(&controlPlane, controlPlaneFinalizer)
		if err := r.Update(ctx, &controlPlane); err != nil {
			return ctrl.Result{}, err
		}
	}

	if err := r.ensureManagementNamespace(ctx, &controlPlane); err != nil {
		return ctrl.Result{}, err
	}

	if controlPlane.Spec.ClassRef != nil && controlPlane.Spec.ClassRef.Name != "" {
		var classObj controlplanev1alpha1.ControlPlaneClass
		if err := r.Get(ctx, client.ObjectKey{Name: controlPlane.Spec.ClassRef.Name}, &classObj); err != nil {
			if apierrors.IsNotFound(err) {
				return r.updateStatus(ctx, &controlPlane, "", nil, conditionReady(
					metav1.ConditionFalse,
					"ClassNotFound",
					fmt.Sprintf("ControlPlaneClass %q not found", controlPlane.Spec.ClassRef.Name),
				))
			}
			return ctrl.Result{}, err
		}
	}

	if mode != controlplanev1alpha1.ControlPlaneModeVirtual {
		return r.updateStatus(ctx, &controlPlane, "", nil, conditionReady(
			metav1.ConditionFalse,
			"ModeNotSupported",
			fmt.Sprintf("mode %q is not supported in v0/v1", mode),
		))
	}

	endpoint, err := r.resolveEndpoint(ctx, &controlPlane)
	if err != nil {
		if apierrors.IsNotFound(err) {
			_, _ = r.updateStatus(ctx, &controlPlane, "", nil, conditionReady(
				metav1.ConditionFalse,
				"EndpointPending",
				err.Error(),
			))
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}
	externalEndpoint, err := r.resolveExternalEndpoint(ctx, &controlPlane)
	if err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	if externalEndpoint == "" {
		externalEndpoint = endpoint
	}

	joinEndpoint, err := r.resolveJoinEndpoint(ctx, &controlPlane)
	if err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	if joinEndpoint == "" {
		joinEndpoint = externalEndpoint
	}

	sharedCA, err := r.sharedCAData(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}

	clusterClient, err := r.clusterClientForEndpoint(endpoint)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err := r.bootstrapVirtualCluster(ctx, clusterClient, joinEndpoint, sharedCA); err != nil {
		if isAPIServerNotReady(err) {
			_, _ = r.updateStatus(ctx, &controlPlane, "", nil, conditionReady(
				metav1.ConditionFalse,
				"Bootstrapping",
				err.Error(),
			))
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}
		if apierrors.IsNotFound(err) {
			_, _ = r.updateStatus(ctx, &controlPlane, "", nil, conditionReady(
				metav1.ConditionFalse,
				"Bootstrapping",
				err.Error(),
			))
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	token, err := r.issueAdminToken(ctx, clusterClient)
	if err != nil {
		if isAPIServerNotReady(err) {
			_, _ = r.updateStatus(ctx, &controlPlane, "", nil, conditionReady(
				metav1.ConditionFalse,
				"Bootstrapping",
				err.Error(),
			))
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	internalKubeconfig, err := buildKubeconfig(r.ClusterConfig, endpoint, token)
	if err != nil {
		return ctrl.Result{}, err
	}

	var externalKubeconfig []byte
	if len(sharedCA) > 0 {
		externalKubeconfig, err = buildKubeconfigWithCA(r.ClusterConfig, externalEndpoint, token, sharedCA)
		if err != nil {
			return ctrl.Result{}, err
		}
	} else {
		externalKubeconfig, err = buildKubeconfig(r.ClusterConfig, externalEndpoint, token)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	secretRef, err := r.upsertKubeconfigSecret(ctx, &controlPlane, internalKubeconfig, externalKubeconfig)
	if err != nil {
		return ctrl.Result{}, err
	}

	ready := conditionReady(metav1.ConditionTrue, "Reconciled", "control plane is ready")
	return r.updateStatus(ctx, &controlPlane, endpoint, secretRef, ready)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ControlPlaneReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &controlplanev1alpha1.ControlPlane{}, endpointRefIndexKey, func(obj client.Object) []string {
		cp, ok := obj.(*controlplanev1alpha1.ControlPlane)
		if !ok || cp.Spec.EndpointRef == nil || cp.Spec.EndpointRef.Name == "" {
			return nil
		}
		return []string{cp.Spec.EndpointRef.Name}
	}); err != nil {
		return err
	}

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &controlplanev1alpha1.ControlPlane{}, classRefIndexKey, func(obj client.Object) []string {
		cp, ok := obj.(*controlplanev1alpha1.ControlPlane)
		if !ok || cp.Spec.ClassRef == nil || cp.Spec.ClassRef.Name == "" {
			return nil
		}
		return []string{cp.Spec.ClassRef.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&controlplanev1alpha1.ControlPlane{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.Config.MaxConcurrentReconciles,
		}).
		Watches(&controlplanev1alpha1.ControlPlaneEndpoint{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			var controlPlanes controlplanev1alpha1.ControlPlaneList
			if err := r.List(ctx, &controlPlanes, client.MatchingFields{endpointRefIndexKey: obj.GetName()}); err != nil {
				return nil
			}
			requests := make([]ctrl.Request, 0, len(controlPlanes.Items))
			for i := range controlPlanes.Items {
				requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKey{Name: controlPlanes.Items[i].Name}})
			}
			return requests
		})).
		Watches(&controlplanev1alpha1.ControlPlaneClass{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			var controlPlanes controlplanev1alpha1.ControlPlaneList
			if err := r.List(ctx, &controlPlanes, client.MatchingFields{classRefIndexKey: obj.GetName()}); err != nil {
				return nil
			}
			requests := make([]ctrl.Request, 0, len(controlPlanes.Items))
			for i := range controlPlanes.Items {
				requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKey{Name: controlPlanes.Items[i].Name}})
			}
			return requests
		})).
		Named("controlplane").
		Complete(r)
}

const (
	controlPlaneFinalizer = "controlplane.kplane.dev/finalizer"
	defaultNSPrefix       = "kplane-cp-"
	defaultAdminNamespace = "kplane-system"
	defaultAdminSAName    = "controlplane-admin"
	defaultAdminCRBName   = "controlplane-admin"
	clusterSigningSecret  = "kplane-cluster-signing-keys"
	clusterSigningCAKey   = "ca.crt"
	clusterSigningCAFile  = "/var/run/kplane/cluster-signing/ca.crt"
	endpointRefIndexKey   = ".spec.endpointRef.name"
	classRefIndexKey      = ".spec.classRef.name"
)

func (r *ControlPlaneReconciler) managementNamespace(controlPlane *controlplanev1alpha1.ControlPlane) string {
	prefix := r.Config.ManagementNamespacePrefix
	if prefix == "" {
		prefix = defaultNSPrefix
	}
	name := prefix + controlPlane.Name
	if len(name) <= 63 {
		return name
	}
	hash := sha256.Sum256([]byte(controlPlane.Name))
	suffix := hex.EncodeToString(hash[:4])
	trunc := controlPlane.Name
	if len(trunc) > 40 {
		trunc = trunc[:40]
	}
	name = fmt.Sprintf("%s%s-%s", prefix, trunc, suffix)
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}

func (r *ControlPlaneReconciler) ensureManagementNamespace(ctx context.Context, controlPlane *controlplanev1alpha1.ControlPlane) error {
	name := r.managementNamespace(controlPlane)
	var namespace corev1.Namespace
	if err := r.Get(ctx, client.ObjectKey{Name: name}, &namespace); err == nil {
		return nil
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	namespace = corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"controlplane.kplane.dev/name": controlPlane.Name,
			},
		},
	}
	return r.Create(ctx, &namespace)
}

func (r *ControlPlaneReconciler) reconcileDelete(ctx context.Context, controlPlane *controlplanev1alpha1.ControlPlane) error {
	log := logf.FromContext(ctx)
	clusterPath, _ := clusterPathForControlPlane(controlPlane)

	policy := deletionPolicyFor(controlPlane, nil)
	if controlPlane.Spec.ClassRef != nil && controlPlane.Spec.ClassRef.Name != "" {
		var class controlplanev1alpha1.ControlPlaneClass
		if err := r.Get(ctx, client.ObjectKey{Name: controlPlane.Spec.ClassRef.Name}, &class); err == nil {
			policy = deletionPolicyFor(controlPlane, &class)
		}
	}

	if policy == controlplanev1alpha1.DeletionPolicyDestroy {
		if endpoint, err := r.resolveEndpoint(ctx, controlPlane); err == nil {
			if clusterClient, err := r.clusterClientForEndpoint(endpoint); err == nil {
				_ = clusterClient.CoreV1().ServiceAccounts(r.virtualAdminNamespace()).Delete(ctx, r.virtualAdminSAName(), metav1.DeleteOptions{})
				_ = clusterClient.RbacV1().ClusterRoleBindings().Delete(ctx, r.virtualAdminCRBName(), metav1.DeleteOptions{})
			}
		}
		if err := r.destroyClusterData(ctx, clusterPath); err != nil {
			log.Error(err, "failed to destroy cluster data", "clusterPath", clusterPath)
			return err
		}
	}

	secretName := kubeconfigSecretName(controlPlane.Name)
	secretNamespace := r.managementNamespace(controlPlane)
	_ = r.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: secretNamespace}})
	_ = r.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: secretNamespace}})
	return nil
}

func (r *ControlPlaneReconciler) resolveEndpoint(ctx context.Context, controlPlane *controlplanev1alpha1.ControlPlane) (string, error) {
	ref := controlPlane.Spec.EndpointRef
	if ref == nil || ref.Name == "" {
		return "", apierrors.NewNotFound(schema.GroupResource{
			Group:    controlplanev1alpha1.GroupVersion.Group,
			Resource: "controlplaneendpoints",
		}, "endpointRef not set")
	}

	var endpoint controlplanev1alpha1.ControlPlaneEndpoint
	if err := r.Get(ctx, client.ObjectKey{Name: ref.Name}, &endpoint); err != nil {
		return "", err
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
	}, fmt.Sprintf("endpoint %q is empty", ref.Name))
}

func (r *ControlPlaneReconciler) resolveExternalEndpoint(ctx context.Context, controlPlane *controlplanev1alpha1.ControlPlane) (string, error) {
	ref := controlPlane.Spec.EndpointRef
	if ref == nil || ref.Name == "" {
		return "", apierrors.NewNotFound(schema.GroupResource{
			Group:    controlplanev1alpha1.GroupVersion.Group,
			Resource: "controlplaneendpoints",
		}, "endpointRef not set")
	}

	var endpoint controlplanev1alpha1.ControlPlaneEndpoint
	if err := r.Get(ctx, client.ObjectKey{Name: ref.Name}, &endpoint); err != nil {
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
	}, fmt.Sprintf("endpoint %q is empty", ref.Name))
}

func (r *ControlPlaneReconciler) resolveJoinEndpoint(ctx context.Context, controlPlane *controlplanev1alpha1.ControlPlane) (string, error) {
	ref := controlPlane.Spec.EndpointRef
	if ref == nil || ref.Name == "" {
		return "", apierrors.NewNotFound(schema.GroupResource{
			Group:    controlplanev1alpha1.GroupVersion.Group,
			Resource: "controlplaneendpoints",
		}, "endpointRef not set")
	}

	var endpoint controlplanev1alpha1.ControlPlaneEndpoint
	if err := r.Get(ctx, client.ObjectKey{Name: ref.Name}, &endpoint); err != nil {
		return "", err
	}
	if endpoint.Status.JoinEndpoint != "" {
		return endpoint.Status.JoinEndpoint, nil
	}
	if endpoint.Spec.JoinEndpoint != "" {
		return endpoint.Spec.JoinEndpoint, nil
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
	}, fmt.Sprintf("endpoint %q is empty", ref.Name))
}

func (r *ControlPlaneReconciler) clusterClientForEndpoint(endpoint string) (*kubernetes.Clientset, error) {
	base := r.ClusterConfig
	if base == nil {
		return nil, fmt.Errorf("cluster config is required")
	}
	cfg := rest.CopyConfig(base)
	cfg.Host = endpoint
	return kubernetes.NewForConfig(cfg)
}

func (r *ControlPlaneReconciler) bootstrapVirtualCluster(ctx context.Context, clientset *kubernetes.Clientset, endpoint string, caData []byte) error {
	adminNS := r.virtualAdminNamespace()
	requiredNamespaces := []string{
		"default",
		"kube-system",
		"kube-public",
		"kube-node-lease",
		adminNS,
	}
	seen := make(map[string]struct{}, len(requiredNamespaces))
	for _, ns := range requiredNamespaces {
		if _, ok := seen[ns]; ok {
			continue
		}
		seen[ns] = struct{}{}
		if err := ensureNamespace(ctx, clientset, ns); err != nil {
			return err
		}
	}

	if _, err := clientset.CoreV1().ServiceAccounts(adminNS).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: r.virtualAdminSAName()},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	if _, err := clientset.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: r.virtualAdminCRBName()},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      r.virtualAdminSAName(),
				Namespace: adminNS,
			},
		},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	return r.ensureBootstrapArtifacts(ctx, clientset, endpoint, caData)
}

func ensureNamespace(ctx context.Context, clientset *kubernetes.Clientset, name string) error {
	if _, err := clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (r *ControlPlaneReconciler) issueAdminToken(ctx context.Context, clientset *kubernetes.Clientset) (string, error) {
	expiration := int64((24 * time.Hour).Seconds())
	token, err := clientset.CoreV1().ServiceAccounts(r.virtualAdminNamespace()).CreateToken(
		ctx,
		r.virtualAdminSAName(),
		&authv1.TokenRequest{
			Spec: authv1.TokenRequestSpec{
				ExpirationSeconds: ptr.To(expiration),
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		return "", err
	}
	return token.Status.Token, nil
}

func (r *ControlPlaneReconciler) upsertKubeconfigSecret(ctx context.Context, controlPlane *controlplanev1alpha1.ControlPlane, internalKubeconfig, externalKubeconfig []byte) (*corev1.SecretReference, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kubeconfigSecretName(controlPlane.Name),
			Namespace: r.managementNamespace(controlPlane),
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if secret.Labels == nil {
			secret.Labels = map[string]string{}
		}
		secret.Labels["controlplane.kplane.dev/name"] = controlPlane.Name
		secret.Type = corev1.SecretTypeOpaque
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data["kubeconfig"] = internalKubeconfig
		if len(externalKubeconfig) > 0 {
			secret.Data["kubeconfig-external"] = externalKubeconfig
		}
		return controllerutil.SetControllerReference(controlPlane, secret, r.Scheme)
	})
	if err != nil {
		return nil, err
	}
	return &corev1.SecretReference{Name: secret.Name, Namespace: secret.Namespace}, nil
}

func (r *ControlPlaneReconciler) updateStatus(ctx context.Context, controlPlane *controlplanev1alpha1.ControlPlane, endpoint string, secretRef *corev1.SecretReference, condition metav1.Condition) (ctrl.Result, error) {
	patch := client.MergeFrom(controlPlane.DeepCopy())
	controlPlane.Status.Endpoint = endpoint
	controlPlane.Status.KubeconfigSecretRef = secretRef
	controlPlane.Status.ObservedGeneration = controlPlane.Generation
	condition.ObservedGeneration = controlPlane.Generation
	meta.SetStatusCondition(&controlPlane.Status.Conditions, condition)
	if err := r.Status().Patch(ctx, controlPlane, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func conditionReady(status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: 0,
		LastTransitionTime: metav1.Now(),
	}
}

func isAPIServerNotReady(err error) bool {
	if err == nil {
		return false
	}
	if apierrors.IsForbidden(err) || apierrors.IsServiceUnavailable(err) || apierrors.IsTooManyRequests(err) {
		msg := err.Error()
		if strings.Contains(msg, "not yet ready to handle request") ||
			strings.Contains(msg, "apiserver not ready") ||
			strings.Contains(msg, "not yet ready") {
			return true
		}
	}
	return false
}

func (r *ControlPlaneReconciler) virtualAdminNamespace() string {
	if r.Config.VirtualAdminNamespace != "" {
		return r.Config.VirtualAdminNamespace
	}
	return defaultAdminNamespace
}

func (r *ControlPlaneReconciler) virtualAdminSAName() string {
	if r.Config.VirtualAdminServiceAccount != "" {
		return r.Config.VirtualAdminServiceAccount
	}
	return defaultAdminSAName
}

func (r *ControlPlaneReconciler) virtualAdminCRBName() string {
	if r.Config.VirtualAdminClusterRoleBinding != "" {
		return r.Config.VirtualAdminClusterRoleBinding
	}
	return defaultAdminCRBName
}

func kubeconfigSecretName(name string) string {
	base := fmt.Sprintf("controlplane-%s-kubeconfig", name)
	if len(base) <= 63 {
		return base
	}
	hash := sha256.Sum256([]byte(name))
	suffix := hex.EncodeToString(hash[:4])
	trunc := name
	if len(trunc) > 30 {
		trunc = trunc[:30]
	}
	base = fmt.Sprintf("cp-%s-kubeconfig-%s", trunc, suffix)
	if len(base) > 63 {
		return base[:63]
	}
	return base
}

func buildKubeconfig(cfg *rest.Config, endpoint, token string) ([]byte, error) {
	return buildKubeconfigWithCA(cfg, endpoint, token, nil)
}

func buildKubeconfigWithCA(cfg *rest.Config, endpoint, token string, caData []byte) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if len(caData) == 0 {
		var err error
		caData, err = caDataFromConfig(cfg)
		if err != nil {
			return nil, err
		}
	}
	clusterName := "controlplane"
	userName := "admin"
	contextName := "controlplane"
	kcfg := api.Config{
		Clusters: map[string]*api.Cluster{
			clusterName: {
				Server:                   endpoint,
				CertificateAuthorityData: caData,
				InsecureSkipTLSVerify:    cfg.Insecure && len(caData) == 0,
			},
		},
		AuthInfos: map[string]*api.AuthInfo{
			userName: {
				Token: token,
			},
		},
		Contexts: map[string]*api.Context{
			contextName: {
				Cluster:  clusterName,
				AuthInfo: userName,
			},
		},
		CurrentContext: contextName,
	}
	return clientcmd.Write(kcfg)
}

func caDataFromConfig(cfg *rest.Config) ([]byte, error) {
	if len(cfg.CAData) > 0 {
		return cfg.CAData, nil
	}
	if cfg.CAFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (r *ControlPlaneReconciler) sharedCAData(ctx context.Context) ([]byte, error) {
	var secret corev1.Secret
	if err := r.Get(ctx, client.ObjectKey{Namespace: r.virtualAdminNamespace(), Name: clusterSigningSecret}, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			if data, fileErr := os.ReadFile(clusterSigningCAFile); fileErr == nil && len(data) > 0 {
				return data, nil
			}
			// Fall back to manager config CA data if available.
			return caDataFromConfig(r.ClusterConfig)
		}
		return nil, err
	}
	data := secret.Data[clusterSigningCAKey]
	if len(data) == 0 {
		if fileData, fileErr := os.ReadFile(clusterSigningCAFile); fileErr == nil && len(fileData) > 0 {
			return fileData, nil
		}
		return nil, fmt.Errorf("missing %s in secret %s/%s", clusterSigningCAKey, secret.Namespace, secret.Name)
	}
	return data, nil
}

func (r *ControlPlaneReconciler) ensureBootstrapArtifacts(ctx context.Context, clientset *kubernetes.Clientset, endpoint string, caData []byte) error {
	host := endpointHost(endpoint)
	if host == "" {
		return fmt.Errorf("invalid endpoint %q: missing host", endpoint)
	}

	if err := ensureKubeadmConfig(ctx, clientset, host); err != nil {
		return err
	}
	if err := ensureKubeletConfig(ctx, clientset); err != nil {
		return err
	}
	if err := ensureClusterInfo(ctx, clientset, endpoint, caData); err != nil {
		return err
	}
	if err := ensureBootstrapToken(ctx, clientset); err != nil {
		return err
	}
	return ensureBootstrapRBAC(ctx, clientset)
}

func endpointHost(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return ""
}

func ensureKubeadmConfig(ctx context.Context, clientset *kubernetes.Clientset, host string) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubeadm-config",
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"ClusterConfiguration": fmt.Sprintf(`apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
clusterName: virtual
controlPlaneEndpoint: %s
`, host),
		},
	}
	_, err := clientset.CoreV1().ConfigMaps("kube-system").Create(ctx, cm, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func ensureKubeletConfig(ctx context.Context, clientset *kubernetes.Clientset) error {
	kubeletConfig := `apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
failSwapOn: false
serverTLSBootstrap: true
`
	cmClient := clientset.CoreV1().ConfigMaps("kube-system")
	cm, err := cmClient.Get(ctx, "kubelet-config", metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kubelet-config",
				Namespace: "kube-system",
			},
			Data: map[string]string{
				"kubelet": kubeletConfig,
			},
		}
		_, err = cmClient.Create(ctx, cm, metav1.CreateOptions{})
		return err
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data["kubelet"] = kubeletConfig
	_, err = cmClient.Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

func ensureClusterInfo(ctx context.Context, clientset *kubernetes.Clientset, endpoint string, caData []byte) error {
	if len(caData) == 0 {
		return fmt.Errorf("ca data is required for cluster-info")
	}
	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: %s
    certificate-authority-data: %s
contexts:
- name: cluster
  context:
    cluster: cluster
    user: ""
current-context: cluster
users: []
`, endpoint, encodeBase64(caData))

	cmClient := clientset.CoreV1().ConfigMaps("kube-public")
	cm, err := cmClient.Get(ctx, "cluster-info", metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cluster-info",
				Namespace: "kube-public",
			},
			Data: map[string]string{
				"kubeconfig": kubeconfig,
			},
		}
		_, err = cmClient.Create(ctx, cm, metav1.CreateOptions{})
		return err
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data["kubeconfig"] = kubeconfig
	_, err = cmClient.Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

func ensureBootstrapToken(ctx context.Context, clientset *kubernetes.Clientset) error {
	tokenID := utilrand.String(6)
	tokenSecret := utilrand.String(16)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bootstrap-token-" + tokenID,
			Namespace: "kube-system",
		},
		Type: "bootstrap.kubernetes.io/token",
		StringData: map[string]string{
			"token-id":                       tokenID,
			"token-secret":                   tokenSecret,
			"usage-bootstrap-authentication": "true",
			"usage-bootstrap-signing":        "true",
			"auth-extra-groups":              "system:bootstrappers,system:bootstrappers:kubeadm:default-node-token",
		},
	}
	_, err := clientset.CoreV1().Secrets("kube-system").Create(ctx, secret, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func ensureBootstrapRBAC(ctx context.Context, clientset *kubernetes.Clientset) error {
	if err := ensurePublicInfoViewer(ctx, clientset); err != nil {
		return err
	}
	if err := ensureKubeadmBootstrapperRole(ctx, clientset); err != nil {
		return err
	}
	if err := ensureNodeRBAC(ctx, clientset); err != nil {
		return err
	}

	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "system:node-bootstrapper"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"certificates.k8s.io"},
				Resources: []string{"certificatesigningrequests", "certificatesigningrequests/nodeclient"},
				Verbs:     []string{"create", "get", "list", "watch"},
			},
		},
	}
	_, err := clientset.RbacV1().ClusterRoles().Create(ctx, clusterRole, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "system:node-bootstrapper"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:node-bootstrapper",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "Group",
				Name: "system:bootstrappers",
			},
			{
				Kind: "Group",
				Name: "system:bootstrappers:kubeadm:default-node-token",
			},
		},
	}
	_, err = clientset.RbacV1().ClusterRoleBindings().Create(ctx, clusterRoleBinding, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bootstrap-token-cluster-info",
			Namespace: "kube-public",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:public-info-viewer",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "Group",
				Name: "system:bootstrappers",
			},
			{
				Kind: "Group",
				Name: "system:bootstrappers:kubeadm:default-node-token",
			},
		},
	}
	_, err = clientset.RbacV1().RoleBindings("kube-public").Create(ctx, roleBinding, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func ensurePublicInfoViewer(ctx context.Context, clientset *kubernetes.Clientset) error {
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "system:public-info-viewer"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
	_, err := clientset.RbacV1().ClusterRoles().Create(ctx, clusterRole, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func ensureKubeadmBootstrapperRole(ctx context.Context, clientset *kubernetes.Clientset) error {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubeadm-bootstrapper",
			Namespace: "kube-system",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
	_, err := clientset.RbacV1().Roles("kube-system").Create(ctx, role, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubeadm-bootstrapper",
			Namespace: "kube-system",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "kubeadm-bootstrapper",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "Group",
				Name: "system:bootstrappers",
			},
			{
				Kind: "Group",
				Name: "system:bootstrappers:kubeadm:default-node-token",
			},
		},
	}
	_, err = clientset.RbacV1().RoleBindings("kube-system").Create(ctx, roleBinding, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func ensureNodeRBAC(ctx context.Context, clientset *kubernetes.Clientset) error {
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "system:node"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"create", "get", "list", "watch", "update", "patch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"nodes/status"},
				Verbs:     []string{"update", "patch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods/status"},
				Verbs:     []string{"update", "patch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"services", "endpoints", "configmaps", "secrets"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"coordination.k8s.io"},
				Resources: []string{"leases"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
			},
			{
				APIGroups: []string{"storage.k8s.io"},
				Resources: []string{"csidrivers"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"node.k8s.io"},
				Resources: []string{"runtimeclasses"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch", "update"},
			},
		},
	}
	_, err := clientset.RbacV1().ClusterRoles().Create(ctx, clusterRole, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "system:nodes"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:node",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "Group",
				Name: "system:nodes",
			},
		},
	}
	_, err = clientset.RbacV1().ClusterRoleBindings().Create(ctx, clusterRoleBinding, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func encodeBase64(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

func clusterPathForControlPlane(controlPlane *controlplanev1alpha1.ControlPlane) (string, error) {
	clusterPath := controlPlane.Name
	if controlPlane.Spec.Virtual != nil && controlPlane.Spec.Virtual.ClusterPath != "" {
		clusterPath = controlPlane.Spec.Virtual.ClusterPath
	}
	if errs := validation.IsDNS1123Label(clusterPath); len(errs) > 0 {
		msg := strings.Join(errs, "; ")
		return clusterPath, fmt.Errorf("invalid cluster path %q: %s", clusterPath, msg)
	}
	return clusterPath, nil
}

func deletionPolicyFor(controlPlane *controlplanev1alpha1.ControlPlane, class *controlplanev1alpha1.ControlPlaneClass) controlplanev1alpha1.DeletionPolicy {
	if controlPlane.Spec.DeletionPolicy != "" {
		return controlPlane.Spec.DeletionPolicy
	}
	if class != nil && class.Spec.DeletionPolicy != nil && *class.Spec.DeletionPolicy != "" {
		return *class.Spec.DeletionPolicy
	}
	return controlplanev1alpha1.DeletionPolicyRetain
}

func (r *ControlPlaneReconciler) destroyClusterData(ctx context.Context, clusterID string) error {
	if len(r.Config.EtcdEndpoints) == 0 {
		return fmt.Errorf("etcdEndpoints not configured for destroy deletion policy")
	}
	prefix := strings.TrimSuffix(r.Config.EtcdPrefix, "/")
	if prefix == "" {
		prefix = "/registry"
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	keyPrefix := prefix + "/"
	clusterSegment := "/clusters/" + clusterID + "/"

	etcdClient, err := clientv3.New(clientv3.Config{
		Endpoints:   r.Config.EtcdEndpoints,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return err
	}
	defer func() {
		_ = etcdClient.Close()
	}()

	startKey := keyPrefix
	deleted := 0
	for {
		resp, err := etcdClient.Get(ctx, startKey, clientv3.WithRange(clientv3.GetPrefixRangeEnd(keyPrefix)), clientv3.WithLimit(1000))
		if err != nil {
			return err
		}
		for _, kv := range resp.Kvs {
			key := string(kv.Key)
			if strings.Contains(key, clusterSegment) {
				if _, err := etcdClient.Delete(ctx, key); err != nil {
					return err
				}
				deleted++
			}
		}
		if !resp.More {
			break
		}
		startKey = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}

	logf.FromContext(ctx).Info("destroyed cluster data", "clusterID", clusterID, "deletedKeys", deleted)
	return nil
}
