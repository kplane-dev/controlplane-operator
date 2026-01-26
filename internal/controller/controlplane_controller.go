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
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

	clusterPath := controlPlane.Name
	if controlPlane.Spec.Virtual != nil && controlPlane.Spec.Virtual.ClusterPath != "" {
		clusterPath = controlPlane.Spec.Virtual.ClusterPath
	}

	if errs := validation.IsDNS1123Label(clusterPath); len(errs) > 0 {
		msg := strings.Join(errs, "; ")
		log.Error(fmt.Errorf("invalid cluster path"), "clusterPath validation failed", "clusterPath", clusterPath)
		return r.updateStatus(ctx, &controlPlane, "", nil, conditionReady(
			metav1.ConditionFalse,
			"InvalidClusterPath",
			msg,
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
		var class controlplanev1alpha1.ControlPlaneClass
		if err := r.Get(ctx, client.ObjectKey{Name: controlPlane.Spec.ClassRef.Name}, &class); err != nil {
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
	clusterClient, err := r.clusterClientForEndpoint(endpoint)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err := r.bootstrapVirtualCluster(ctx, clusterClient, clusterPath); err != nil {
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

	kubeconfigBytes, err := buildKubeconfig(r.ClusterConfig, endpoint, token)
	if err != nil {
		return ctrl.Result{}, err
	}

	secretRef, err := r.upsertKubeconfigSecret(ctx, &controlPlane, kubeconfigBytes)
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
	if endpoint, err := r.resolveEndpoint(ctx, controlPlane); err == nil {
		if clusterClient, err := r.clusterClientForEndpoint(endpoint); err == nil {
			_ = clusterClient.CoreV1().ServiceAccounts(r.virtualAdminNamespace()).Delete(ctx, r.virtualAdminSAName(), metav1.DeleteOptions{})
			_ = clusterClient.RbacV1().ClusterRoleBindings().Delete(ctx, r.virtualAdminCRBName(), metav1.DeleteOptions{})
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

func (r *ControlPlaneReconciler) clusterClientForEndpoint(endpoint string) (*kubernetes.Clientset, error) {
	base := r.ClusterConfig
	if base == nil {
		return nil, fmt.Errorf("cluster config is required")
	}
	cfg := rest.CopyConfig(base)
	cfg.Host = endpoint
	return kubernetes.NewForConfig(cfg)
}

func (r *ControlPlaneReconciler) bootstrapVirtualCluster(ctx context.Context, clientset *kubernetes.Clientset, clusterPath string) error {
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

	return nil
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

func (r *ControlPlaneReconciler) upsertKubeconfigSecret(ctx context.Context, controlPlane *controlplanev1alpha1.ControlPlane, kubeconfig []byte) (*corev1.SecretReference, error) {
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
		secret.Data["kubeconfig"] = kubeconfig
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
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	caData, err := caDataFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	clusterName := "controlplane"
	userName := "admin"
	contextName := "controlplane"
	kcfg := api.Config{
		Clusters: map[string]*api.Cluster{
			clusterName: {
				Server:                   endpoint,
				CertificateAuthorityData: caData,
				InsecureSkipTLSVerify:    cfg.Insecure,
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
	if len(cfg.TLSClientConfig.CAData) > 0 {
		return cfg.TLSClientConfig.CAData, nil
	}
	if cfg.TLSClientConfig.CAFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(cfg.TLSClientConfig.CAFile)
	if err != nil {
		return nil, err
	}
	return data, nil
}
