//go:build e2e
// +build e2e

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

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kplane-dev/controlplane-operator/test/utils"
)

// namespace where the project is deployed in
const namespace = "kplane-system"

const (
	apiserverName       = "kplane-apiserver"
	apiserverService    = "kplane-apiserver"
	apiserverSecurePort = 6443
)

// serviceAccountName created for the project
const serviceAccountName = "kplane-controlplane-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "kplane-controlplane-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "kplane-controlplane-metrics-binding"

// metricsReaderClusterRoleName is the ClusterRole used to read metrics
const metricsReaderClusterRoleName = "kplane-controlplane-metrics-reader"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "get", "ns", namespace)
		_, err := utils.Run(cmd)
		if err != nil {
			cmd = exec.Command("kubectl", "create", "ns", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")
		}

		By("labeling the namespace to allow apiserver/etcd pods")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=privileged",
			"pod-security.kubernetes.io/warn=privileged",
			"pod-security.kubernetes.io/audit=privileged")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("creating cluster signing keys secret")
		applyKubectlYAML(clusterSigningSecretYAML())

		By("creating apiserver pki secret")
		applyKubectlYAML(apiserverPKISecretYAML())

		By("creating service account signing secret")
		applyKubectlYAML(serviceAccountSigningSecretYAML())

		By("deploying etcd")
		applyKubectlYAML(etcdStackYAML())
		waitForDeploymentReady("kplane-etcd")

		By("deploying the apiserver")
		applyKubectlYAML(apiserverStackYAML())
		waitForDeploymentReady(apiserverName)
		waitForAPIServerPodReady()

		By("creating operator config configmap")
		cmd = exec.Command("kubectl", "create", "configmap", "operator-config",
			"--from-file=operatorconfig.yaml=config/operatorconfig.yaml",
			"-n", namespace,
			"--dry-run=client",
			"-o", "yaml",
		)
		cmYAML, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to render operator-config ConfigMap")
		applyKubectlYAML(cmYAML)

		By("creating apiserver kubeconfig secret")
		tmpFile, err := os.CreateTemp("", "kplane-apiserver-kubeconfig-*.yaml")
		Expect(err).NotTo(HaveOccurred(), "Failed to create kubeconfig temp file")
		_, err = tmpFile.WriteString(apiserverKubeconfigYAML())
		Expect(err).NotTo(HaveOccurred(), "Failed to write kubeconfig")
		Expect(tmpFile.Close()).To(Succeed())
		cmd = exec.Command("kubectl", "create", "secret", "generic", "apiserver-kubeconfig",
			fmt.Sprintf("--from-file=kubeconfig=%s", tmpFile.Name()),
			"-n", namespace,
			"--dry-run=client",
			"-o", "yaml",
		)
		secretYAML, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to render apiserver-kubeconfig Secret")
		applyKubectlYAML(secretYAML)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			if controllerPodName == "" {
				controllerPodName = podNameByLabel("control-plane", "controller-manager")
			}
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}

			By("Fetching ControlPlane resources")
			cmd = exec.Command("kubectl", "get", "controlplane", "-o", "yaml")
			controlPlaneOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "ControlPlanes:\n%s", controlPlaneOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get ControlPlanes: %s", err)
			}

			By("Fetching apiserver logs")
			if apiserverPod := podNameByLabel("app", apiserverName); apiserverPod != "" {
				cmd = exec.Command("kubectl", "logs", apiserverPod, "-n", namespace)
				apiserverLogs, err := utils.Run(cmd)
				if err == nil {
					_, _ = fmt.Fprintf(GinkgoWriter, "Apiserver logs:\n %s", apiserverLogs)
				} else {
					_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get apiserver logs: %s", err)
				}
			}

			By("Fetching etcd logs")
			if etcdPod := podNameByLabel("app", "kplane-etcd"); etcdPod != "" {
				cmd = exec.Command("kubectl", "logs", etcdPod, "-n", namespace)
				etcdLogs, err := utils.Run(cmd)
				if err == nil {
					_, _ = fmt.Fprintf(GinkgoWriter, "Etcd logs:\n %s", etcdLogs)
				} else {
					_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get etcd logs: %s", err)
				}
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				fmt.Sprintf("--clusterrole=%s", metricsReaderClusterRoleName),
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
				"--dry-run=client",
				"-o", "yaml",
			)
			crbYAML, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to render ClusterRoleBinding")
			applyKubectlYAML(crbYAML)

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("waiting for the metrics endpoint to be ready")
			verifyMetricsEndpointReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "endpoints", metricsServiceName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("8443"), "Metrics endpoint is not ready")
			}
			Eventually(verifyMetricsEndpointReady).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("controller-runtime.metrics\tServing metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted).Should(Succeed())

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			verifyMetricsAvailable := func(g Gomega) {
				metricsOutput, err := getMetricsOutput()
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
				g.Expect(metricsOutput).NotTo(BeEmpty())
				g.Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
			}
			Eventually(verifyMetricsAvailable, 2*time.Minute).Should(Succeed())
		})

		It("should bootstrap a virtual control plane and resolve registration", func() {
			controlPlaneName := "demo"
			endpointName := "demo-endpoint"
			registrationName := "demo-registration"

			By("verifying controlplane CRDs are installed")
			verifyControlPlaneCRDs()

			By("creating the ControlPlaneEndpoint")
			applyKubectlYAML(controlPlaneEndpointYAML(endpointName, controlPlaneName))

			By("creating the ControlPlane")
			applyKubectlYAML(controlPlaneYAML(controlPlaneName, endpointName))

			By("waiting for the ControlPlane to be ready")
			waitForControlPlaneReady(controlPlaneName)

			By("creating the ControlPlaneRegistration")
			applyKubectlYAML(controlPlaneRegistrationYAML(registrationName, controlPlaneName, endpointName))

			By("waiting for the ControlPlaneRegistration to resolve")
			waitForRegistrationReady(registrationName)

			By("verifying kubeconfig works against the virtual control plane")
			verifyVirtualControlPlaneAccess(controlPlaneName)
		})

		It("should allow registration migration to a new control plane", func() {
			sourceControlPlane := "demo"
			targetControlPlane := "demo-migrate"
			targetEndpoint := "demo-migrate-endpoint"
			registrationName := "demo-registration"

			By("creating the target ControlPlaneEndpoint")
			applyKubectlYAML(controlPlaneEndpointYAML(targetEndpoint, targetControlPlane))

			By("creating the target ControlPlane")
			applyKubectlYAML(controlPlaneYAML(targetControlPlane, targetEndpoint))

			By("waiting for the target ControlPlane to be ready")
			waitForControlPlaneReady(targetControlPlane)

			By("updating the registration to target the new control plane")
			cmd := exec.Command("kubectl", "patch", "controlplaneregistration", registrationName,
				"--type=merge",
				"-p", fmt.Sprintf(`{"spec":{"controlPlaneRef":{"name":"%s"},"endpointRef":{"name":"%s"}}}`, targetControlPlane, targetEndpoint),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to patch ControlPlaneRegistration")

			By("waiting for the registration to resolve the new endpoint")
			waitForRegistrationEndpoint(registrationName, targetControlPlane)

			By("ensuring the source control plane still exists")
			cmd = exec.Command("kubectl", "get", "controlplane", sourceControlPlane)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks

		// TODO: Customize the e2e test suite with scenarios specific to your project.
		// Consider applying sample/CR(s) and check their status and/or verifying
		// the reconciliation by using the metrics, i.e.:
		// metricsOutput, err := getMetricsOutput()
		// Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
		// Expect(metricsOutput).To(ContainSubstring(
		//    fmt.Sprintf(`controller_runtime_reconcile_total{controller="%s",result="success"} 1`,
		//    strings.ToLower(<Kind>),
		// ))
	})
})

func applyKubectlYAML(yaml string) {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yaml)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to apply manifest")
}

func apiserverKubeconfigYAML() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: apiserver
  cluster:
    server: %s
    insecure-skip-tls-verify: true
contexts:
- name: apiserver
  context:
    cluster: apiserver
    user: apiserver
current-context: apiserver
users:
- name: apiserver
  user:
    client-certificate-data: %s
    client-key-data: %s
`, apiserverServiceURL(), encodeBase64([]byte(apiserverClientCert)), encodeBase64([]byte(apiserverClientKey)))
}

func apiserverServiceURL() string {
	return fmt.Sprintf("https://%s.%s.svc.cluster.local:%d", apiserverService, namespace, apiserverSecurePort)
}

func clusterSigningSecretYAML() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: kplane-cluster-signing-keys
  namespace: %s
type: Opaque
stringData:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    MIIB6TCCAZCgAwIBAgIUV++gLkV4fZ0lrelyTkb7b0Zy+W4wCgYIKoZIzj0EAwIw
    FTETMBEGA1UEAwwKa3BsYW5lLWNhMB4XDTI2MDIwMTAwMDAwMFoXDTM2MDEyOTAw
    MDAwMFowFTETMBEGA1UEAwwKa3BsYW5lLWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0D
    AQcDQgAE1i7Dk6Kfi4qdePGcz0gQ1o0zMeQFHzH4bHNsHnX7xCJj2OeBDtOa2j2a
    3mxx8b0kxxo8ZP6xVIv46CE0HqNTMFEwHQYDVR0OBBYEFN8ipUG6BOVsS0a+14pI
    xwAq4M+4MB8GA1UdIwQYMBaAFN8ipUG6BOVsS0a+14pIxwAq4M+4MA8GA1UdEwEB
    /wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAIsq1tD2O8SuLJw2fG9R3R0cH++3
    1X5xBzJ+Yz7Tup5ZAiEAq4YbiL1W0Z2Q1b4Y7kQ7f7o+JX1YqXOV6t5Wfxz2kZY=
    -----END CERTIFICATE-----
`, namespace)
}

func apiserverPKISecretYAML() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: kplane-apiserver-pki
  namespace: %s
type: Opaque
stringData:
  ca.crt: |
%s
`, namespace, indentMultiline(apiserverCACert, "    "))
}

func serviceAccountSigningSecretYAML() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: kplane-service-account-keys
  namespace: %s
type: Opaque
stringData:
  sa.key: |
%s
  sa.pub: |
%s
`, namespace, indentMultiline(serviceAccountPrivateKey, "    "), indentMultiline(serviceAccountPublicKey, "    "))
}

func etcdStackYAML() string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: kplane-etcd
  namespace: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kplane-etcd
  template:
    metadata:
      labels:
        app: kplane-etcd
    spec:
      containers:
      - name: etcd
        image: quay.io/coreos/etcd:v3.5.12
        imagePullPolicy: IfNotPresent
        env:
        - name: ALLOW_NONE_AUTHENTICATION
          value: "yes"
        - name: ETCD_LISTEN_CLIENT_URLS
          value: "http://0.0.0.0:2379"
        - name: ETCD_ADVERTISE_CLIENT_URLS
          value: "http://kplane-etcd.%s.svc.cluster.local:2379"
        ports:
        - containerPort: 2379
        volumeMounts:
        - name: data
          mountPath: /bitnami/etcd
      volumes:
      - name: data
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: kplane-etcd
  namespace: %s
spec:
  selector:
    app: kplane-etcd
  ports:
  - port: 2379
    targetPort: 2379
`, namespace, namespace, namespace)
}

func apiserverStackYAML() string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %s
  template:
    metadata:
      labels:
        app: %s
    spec:
      containers:
      - name: apiserver
        image: %s
        args:
        - --etcd-servers=http://kplane-etcd.%s.svc.cluster.local:2379
        - --service-cluster-ip-range=10.0.0.0/24
        - --allow-privileged=true
        - --authorization-mode=AlwaysAllow
        - --cert-dir=/tmp/kubernetes
        - --client-ca-file=/var/run/kplane/pki/ca.crt
        - --service-account-issuer=https://kplane-apiserver.kplane-system.svc.cluster.local
        - --service-account-signing-key-file=/var/run/kplane/service-account/sa.key
        - --service-account-key-file=/var/run/kplane/service-account/sa.pub
        - --secure-port=%d
        ports:
        - containerPort: %d
        volumeMounts:
        - name: apiserver-pki
          mountPath: /var/run/kplane/pki
          readOnly: true
        - name: service-account-keys
          mountPath: /var/run/kplane/service-account
          readOnly: true
      volumes:
      - name: apiserver-pki
        secret:
          secretName: kplane-apiserver-pki
      - name: service-account-keys
        secret:
          secretName: kplane-service-account-keys
---
apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
spec:
  selector:
    app: %s
  ports:
  - port: %d
    targetPort: %d
`, apiserverName, namespace, apiserverName, apiserverName, apiserverImage, namespace, apiserverSecurePort, apiserverSecurePort, apiserverService, namespace, apiserverName, apiserverSecurePort, apiserverSecurePort)
}

func waitForDeploymentReady(name string) {
	cmd := exec.Command("kubectl", "rollout", "status", "deployment/"+name, "-n", namespace, "--timeout=5m")
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed waiting for deployment %s", name))
}

func waitForAPIServerPodReady() {
	cmd := exec.Command("kubectl", "wait", "--for=condition=Ready", "pod", "-l", "app=kplane-apiserver",
		"-n", namespace, "--timeout=5m")
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed waiting for apiserver pod readiness")
}

func podNameByLabel(key, value string) string {
	cmd := exec.Command("kubectl", "get", "pods", "-n", namespace, "-l", fmt.Sprintf("%s=%s", key, value),
		"-o", "jsonpath={.items[0].metadata.name}")
	output, err := utils.Run(cmd)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(output)
}

func podPhase(name, podNamespace string) string {
	cmd := exec.Command("kubectl", "get", "pod", name, "-n", podNamespace, "-o", "jsonpath={.status.phase}")
	output, err := utils.Run(cmd)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(output)
}

func verifyControlPlaneCRDs() {
	crds := []string{
		"controlplanes.controlplane.kplane.dev",
		"controlplaneendpoints.controlplane.kplane.dev",
		"controlplaneregistrations.controlplane.kplane.dev",
	}
	for _, crd := range crds {
		cmd := exec.Command("kubectl", "get", "crd", crd)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Missing CRD %s", crd))
	}
}

func controlPlaneEndpointYAML(name, clusterName string) string {
	return fmt.Sprintf(`apiVersion: controlplane.kplane.dev/v1alpha1
kind: ControlPlaneEndpoint
metadata:
  name: %s
spec:
  endpoint: %s
  externalEndpoint: %s
`, name, clusterEndpointURL(clusterName), clusterEndpointURL(clusterName))
}

func controlPlaneYAML(name, endpointName string) string {
	return fmt.Sprintf(`apiVersion: controlplane.kplane.dev/v1alpha1
kind: ControlPlane
metadata:
  name: %s
spec:
  endpointRef:
    name: %s
  mode: Virtual
`, name, endpointName)
}

func controlPlaneRegistrationYAML(name, controlPlaneName, endpointName string) string {
	return fmt.Sprintf(`apiVersion: controlplane.kplane.dev/v1alpha1
kind: ControlPlaneRegistration
metadata:
  name: %s
spec:
  controlPlaneRef:
    name: %s
  endpointRef:
    name: %s
  services:
    - Controllers
    - Scheduler
  mode: Shared
`, name, controlPlaneName, endpointName)
}

func clusterEndpointURL(clusterName string) string {
	return fmt.Sprintf("%s/clusters/%s/control-plane", apiserverServiceURL(), clusterName)
}

func waitForControlPlaneReady(name string) {
	verifyReady := func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "controlplane", name,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		if output != "True" {
			cmd = exec.Command("kubectl", "get", "controlplane", name, "-o", "yaml")
			statusOutput, statusErr := utils.Run(cmd)
			if statusErr == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "ControlPlane status:\n%s\n", statusOutput)
			}
		}
		g.Expect(output).To(Equal("True"))
	}
	Eventually(verifyReady, 4*time.Minute, 2*time.Second).Should(Succeed())
}

func waitForRegistrationReady(name string) {
	verifyReady := func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "controlplaneregistration", name,
			"-o", "jsonpath={.status.ready}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("true"))
	}
	Eventually(verifyReady, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func waitForRegistrationEndpoint(name, clusterName string) {
	expected := clusterEndpointURL(clusterName)
	verifyEndpoint := func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "controlplaneregistration", name,
			"-o", "jsonpath={.status.resolvedEndpoint}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal(expected))
	}
	Eventually(verifyEndpoint, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func controlPlaneKubeconfigRef(controlPlaneName string) (string, string) {
	cmd := exec.Command("kubectl", "get", "controlplane", controlPlaneName,
		"-o", "jsonpath={.status.kubeconfigSecretRef.name}")
	secretName, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to read kubeconfig secret name")
	cmd = exec.Command("kubectl", "get", "controlplane", controlPlaneName,
		"-o", "jsonpath={.status.kubeconfigSecretRef.namespace}")
	secretNamespace, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to read kubeconfig secret namespace")
	return strings.TrimSpace(secretName), strings.TrimSpace(secretNamespace)
}

func verifyVirtualControlPlaneAccess(controlPlaneName string) {
	podName := "vcp-smoke"
	endpoint := clusterEndpointURL(controlPlaneName) + "/readyz"

	cmd := exec.Command("kubectl", "delete", "pod", podName, "-n", namespace, "--ignore-not-found")
	_, _ = utils.Run(cmd)

	overrides := fmt.Sprintf(`{
  "spec": {
    "restartPolicy": "Never",
    "containers": [{
      "name": "curl",
      "image": "curlimages/curl:latest",
      "command": ["/bin/sh", "-c"],
      "args": ["curl -k -s --connect-timeout 5 --max-time 10 -o /dev/null -w '%%{http_code}' %s"]
    }]
  }
}`, endpoint)

	cmd = exec.Command("kubectl", "run", podName,
		"--restart=Never",
		"--namespace", namespace,
		"--image=curlimages/curl:latest",
		"--overrides", overrides,
	)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to create virtual control plane smoke pod")

	Eventually(func(g Gomega) {
		phase := podPhase(podName, namespace)
		g.Expect(phase).NotTo(BeEmpty())
		g.Expect(phase == "Succeeded" || phase == "Failed").To(BeTrue())
		if phase == "Failed" {
			cmd = exec.Command("kubectl", "logs", podName, "-n", namespace)
			output, _ := utils.Run(cmd)
			g.Expect(fmt.Sprintf("pod failed: %s", output)).To(BeEmpty())
		}
	}).WithTimeout(3 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())

	cmd = exec.Command("kubectl", "logs", podName, "-n", namespace)
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to read virtual control plane smoke pod logs")
	status := strings.TrimSpace(output)
	Expect(status == "200" || status == "401" || status == "403").To(BeTrue())

	cmd = exec.Command("kubectl", "delete", "pod", podName, "-n", namespace, "--ignore-not-found")
	_, _ = utils.Run(cmd)
}

func encodeBase64(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

func indentMultiline(value, indent string) string {
	lines := strings.Split(strings.TrimRight(value, "\n"), "\n")
	for i, line := range lines {
		lines[i] = indent + line
	}
	return strings.Join(lines, "\n")
}

const (
	apiserverCACert = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUPEzWvJz/AvTZ6OqGRIiTqK7U0iIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJa3BsYW5lLWNhMB4XDTI2MDIwMzA3MjgwMVoXDTM2MDIw
MTA3MjgwMVowFDESMBAGA1UEAwwJa3BsYW5lLWNhMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAvicxo3fRJykZo/gsWYSxvoxts7CV/qYk6UPn611aq1YL
gHMsthcgl5TvkiKflJ3wjamnsow0w5aFR29ODsm3hsKxkJzQKUJGV2c5cNepTEeA
zbctK7PLSbrHo9MuuKCjHhN7rX1WzgTRsBbDBr1wZbeGSOlLxcSRYiJZdDwTFvYC
VCa2BIie8Gk8ilCnvJjEYC7opkLcpwJIhG+bh9pyYi5DdYdw0fif9QF640ODg7Di
jTqjb3+6YhwtqDlt9mbIZIuKtTsMtgz5Hb9Z1K1FJ5weuPXJPcR9mhbOiWoeSuLR
nQq2GHvD8Y4tdjYoewLrRCKk5GVM5J3+Cp6XnQDH1QIDAQABo1MwUTAdBgNVHQ4E
FgQUbivtJvPZTm/bAkStuqrkRo+2ROIwHwYDVR0jBBgwFoAUbivtJvPZTm/bAkSt
uqrkRo+2ROIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAEdOa
sXe07+iQAhK8pwqXmH5JAjwigEQOb6oN5noUbcQyYY21UDSdfqegx6ZY16/b3k8G
FJPcaHQqiHjTSQjq4wyfV7wkXD/3kyoZ50wkhATRcyHlZW4I/yAfuNHvfUJWXtmi
y9eeS/ireUpRAm6+zamIou87uu6xWEk1eOvjZ5oBvsrKymM1FuDcCEE1LaTzv30A
PdJfW/Yr215xuxFoTEFcxiYKsCdF3RIyaWPab9TQO57lLsAj8DQ4CVPHxO009Ngg
naL9PlHeF6Z/kBl7GuwxcDywDBj6tzkfy5l2jA8p9tLl0Wm73X2S05n2twlekHaq
OdZBODnpsHQN+sbzQA==
-----END CERTIFICATE-----`

	apiserverClientCert = `-----BEGIN CERTIFICATE-----
MIICxDCCAawCFBxxrAnNsLqWwhqm7H4LzCr/XCsxMA0GCSqGSIb3DQEBCwUAMBQx
EjAQBgNVBAMMCWtwbGFuZS1jYTAeFw0yNjAyMDMwNzI4MDFaFw0zNjAyMDEwNzI4
MDFaMCkxDjAMBgNVBAMMBWFkbWluMRcwFQYDVQQKDA5zeXN0ZW06bWFzdGVyczCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK6He06trY8Jn+1jmNQk+p9u
8E9psMcCzQShh7gi6jGAdguuOGVgSU1L+Ukrlafr0K0baVP3/n93lmlcWtdKAhmo
bOl2GGRCJN5rMe7dp3w/pA4/L3AuD/Pijvubs7+E3+y4r5cZoIkk4hSXFfXoYCN8
CbgSM4kdfTyCw6F58mW+b/OaYO8amS7ezNwAZyJAQQQQTVxiAvpqT1vj0J4kYL+z
CYCI+4IfJ5Z2YzGBgr6fB4X9DmEROHk1yXzNSP9+q3fBpI7pQurKodnTYZ5Yw3ud
c72ticGFJFL5q9LXk3GX40v0N+clSqOq7g2AdQpKdr2d39vqUtFJG5/L2ga0wJEC
AwEAATANBgkqhkiG9w0BAQsFAAOCAQEAepT3gGmXaoofBYLYQrqOVPd+MdhA9/Hz
g3d90DOA8N5n1EmA4gpolUrr2Rbimb5EdzzjSWnKpThOFuiLGTrxxRSfcyL5nfza
L/zSZCe0OTn6LFh+tIdqdJgm0+/wyz6JL6YwMXIQA0HfJwdhHKvStZl2Bpdt1VxF
pvhj2aU9Ipj1wWpooeyG84AvpAmzNikjOwVJ+15tSq5Uc7g3rZuWkWcVNEHRd+OQ
ziZGEjf+LVvF7gDSwSxdjaqgjaMM0EE1+w6uiK57Vegiu17ZnYENv7kBCuEhctsh
ROXYOvYpx9lqk8+ODmiF3lqjPSGnDLbXwmbjJnfDJtNuBeEYPS1T2g==
-----END CERTIFICATE-----`

	apiserverClientKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCuh3tOra2PCZ/t
Y5jUJPqfbvBPabDHAs0EoYe4IuoxgHYLrjhlYElNS/lJK5Wn69CtG2lT9/5/d5Zp
XFrXSgIZqGzpdhhkQiTeazHu3ad8P6QOPy9wLg/z4o77m7O/hN/suK+XGaCJJOIU
lxX16GAjfAm4EjOJHX08gsOhefJlvm/zmmDvGpku3szcAGciQEEEEE1cYgL6ak9b
49CeJGC/swmAiPuCHyeWdmMxgYK+nweF/Q5hETh5Ncl8zUj/fqt3waSO6ULqyqHZ
02GeWMN7nXO9rYnBhSRS+avS15Nxl+NL9DfnJUqjqu4NgHUKSna9nd/b6lLRSRuf
y9oGtMCRAgMBAAECggEAAKzbq0v3uImAft7Bbr5eMpiAQZCAuI7p7STzKEmqgPj/
mjwE33gqZXz6J2zsCCvxGYCrGBmf3YT2UdPFTXcImU9JlaLNg7ldQuOOs9G/jtiv
3sYimMVGHVDVa0GFTL7w4ob33eQGkgBrqRPWkFwf34QdQdPeudtro8AOSkidu/bE
coQb31DxItL4HLOMGsz6aXNVx2KyHemjBmQDdg5O8H4qxi9KIJbScvkdPtjkZIF3
pm51gZOGDLGmw6ymdyvF5WfN3Qwt0O2en81oyhldTNno0EethXOfcAoJtknrpc5r
2Y9iNe19U5lshncJmBLLkMzkKDm9CFek5WF3VIzU8wKBgQD0YbjF/UmV2oM3/rpP
Wd0zumXc0H1dP0CihDa837ZWpKpiSQXnOcY9UePKeRUVVSArSElTaMpTVTclET98
5+c/FM8UdWvYt7f9pz7SmxL9hrLLzqT0YHOHrFRVZK/L9/8+mNc5DrAXjkSKZO1J
judOrGMLWTg9F+gUleP1c3zfDwKBgQC205yA7cC4iFrZS53c3yBwdxA1oYvtrc7K
LKJOeQXqy2chqtBSST+pZ71/pp2a5XqO3Zhfj4kIeKfasSxbe9079J0OMKtHcbxy
/UYjXrrV0E3p7YcY0nS/00EudVQHaXp9Be9Jq6vqbochX2sENMU31UCPGT1DNbTo
I7YgjaJmXwKBgAG748S73FbM2xt9mjLP72rbird7XzhXJ40/pOfIKpIIzxCtdfZD
Ca4Ls7MPEuA432aPN734w169/wsrSSkIuDJRYnrBroc2Hn8VPbPe186mswQRLkhx
msA+r8Z/VWP8GXqHORe1i/hO0RuuRaS899UuEfHVqzl7vvDOc3SdYihvAoGAOMAQ
6XhjhSRWRvMQ6nmcQSzELFGb9Mgp01nte7xXWN2QgsPZ7GDuUPBxwwj+DRHEbEpe
vPL6D1YcjGbIpREayDyS78+tqvykCXGS7vG9vxbsyHtBnzPcp5q0te4XikF0kxBf
iZevQpLSgUp0FpcmzMD2TDUCbjVilVhYdVxhl7MCgYEAh7aZsWvjCOwYJ4UlFGxB
bmuPWVsCvSBM0H3TuG8S5iZTtdzNfDP7HDoF8+bOW2BjuVHv+/d50BdlJF6NM1ZE
sfxkU2d53Hbt4W9sOpUyX3ryscrzFQg5meWraUb8Z8mULa8wTv73T7ZcJV1LCF/D
SQu5UTJeXt7wVwW6a5PaW7g=
-----END PRIVATE KEY-----`

	serviceAccountPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfqsCYa26HZndx
JP2IeGy7OPXMu9oqFyLXP+EpjVgObhcboR/yhJMXfnQST8pwtHImpWG2GE+BFyaI
P3oJQuIiRqaozmUX8HlOSbKplxP3+QnAL+KAdNf9i4IQseuRw4Cp9aCR7CRuNSkR
8KTHay62FgB6JxSAue1NZHVkfwxSKQ+BRLCNcohRqWW77/aBh1DtjFnyhrqzDa84
uYFB+y4eIpSO5Sl480994wm3LEsUPc/FEaJqckGyZsM0KwnuomhLoVhYaz1hnAY8
DvKlV/VtReEtyHv99RxXzTGjjN2fT5GnL2F7T2v8lvkVoFNhZpRWRQB4G1q2FnqO
WAfQudPFAgMBAAECggEABfbK2uaoakZZj9Bh6AcXiKbIB628qHXUx1WLg5HUCDX0
hwOtvdFV7Tq7+zMfzLXwzaC/1Z1y2s+SkOROGqp05/LbptKO1CYXYeU+1zbdeBXF
V3hybXnv13iukxESS4+R7sdOCCVZ9wPlVNY4UXqfdA2+VtG+4lAPnSRzfh2AyFDR
MbXV1gHKv7Vwdvveq4IKFk1iwPsoytu0jC4UhYVlCnQb9EWkybWh+Qv2FkA0lMTr
p217i4Ctj8JB6zrdcKi4ShATqNy4JKWom89gAr01HPvsCuYyJeUUflSwRLcpSXFk
1WoMJAnvDH7PEJFZU94I6/bd45p3pDtL7j8y1MewwQKBgQDW11rEUPUJ9lQrcvmc
6G9IIBfoSGQoz6icR3W+V69+jaGSH1nuKX//hWkxdqdODTk7wjZSdh7mLfkvbTr9
hxnOyTGcZeznXgUozwVVd0R2OAL48AKz/GfUqeUJju6SISBa1iFeBl5ghRRZcwrB
iFwYz3jCsIWRXPQUA27a2hU7UwKBgQC+QXCpvjPLKspVbif0bzCMHPyzFxyHOEH/
tm2EoU+Z1CX8iiXkXxe83eu2joCCXQfhXEERGzRKvVX6Gu8kTB5Aie12aUBShlQ5
TGlsb585inyGe3JuD9rVi3uLfUDN8IS6SaRwakRhzRFPYvWUphMvL9A7AvJPVydn
N8KUSTPphwKBgAuLs0MNnr2UUV2sZiG6lBBqOR6wlUFkN4l+haNfDv1cGyzBJpIY
BNr0jnysBb26FDNT8ptn4a05F0UnN55cXlSwl0vyZlLgyKIyzfST3kgEJpS+QUbu
752MK9Thq4yK3zRCgbSN3xCM1lUgS5mu/FQRAkpkNiljt3JD5Pc59R4lAoGBALKV
4Lgkpp9lmilYzj5ehJZwuy8sWYX/48uxJNojRQHjJokH8AuOy0xoj1J8Ltqvkq8S
lq0E+S/Sy7qJv8I1hQwVrAXDRDJyjup99FNp727mtH7Tr5TqYwKh/CTyPHtS8nOe
nrE6vteC02XOQTD4NvfLDM3ntSWObJkxuP7SO91PAoGAMaolLBzEP7dWef5Hg3Jd
mMOWR351pzSRBXkBQhmzUeHIloEE4yQtEQHWvV2RJd7OTlbj+H6ucBnnbnrQzAkg
tQY94wx10R7eGsGe3NQweQCca+bIX6nb0qXGegPGt4cXehBQJuvinvJrazku40TG
tWFDILdUUqEsoMeLVaCod88=
-----END PRIVATE KEY-----`

	serviceAccountPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn6rAmGtuh2Z3cST9iHhs
uzj1zLvaKhci1z/hKY1YDm4XG6Ef8oSTF350Ek/KcLRyJqVhthhPgRcmiD96CULi
IkamqM5lF/B5TkmyqZcT9/kJwC/igHTX/YuCELHrkcOAqfWgkewkbjUpEfCkx2su
thYAeicUgLntTWR1ZH8MUikPgUSwjXKIUallu+/2gYdQ7YxZ8oa6sw2vOLmBQfsu
HiKUjuUpePNPfeMJtyxLFD3PxRGianJBsmbDNCsJ7qJoS6FYWGs9YZwGPA7ypVf1
bUXhLch7/fUcV80xo4zdn0+Rpy9he09r/Jb5FaBTYWaUVkUAeBtathZ6jlgH0LnT
xQIDAQAB
-----END PUBLIC KEY-----`
)

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() (string, error) {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	return utils.Run(cmd)
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
