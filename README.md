# controlplane-operator
Control plane infrastructure operator for Kplane. It manages the control plane
stack (etcd + shared apiserver), publishes API endpoints, and produces
kubeconfig secrets that downstream services can consume through
`ControlPlaneRegistration`.

## What this repo contains
- **CRDs**: `ControlPlane`, `ControlPlaneClass`, `ControlPlaneEndpoint`,
  `ControlPlaneRegistration`.
- **Controllers** that reconcile control plane infra and registration resolution.
- **E2E tests** that boot a virtual control plane, smoke it, and validate
  registration migration.

For the design details, see:
- `docs/controlplane-operator-design.md`
- `docs/kplane-cli-design.md`

## Quickstart (local dev)

### Prerequisites
- Go 1.24+
- Docker
- kubectl
- kind

### Build and deploy the operator
```sh
make docker-build IMG=<registry>/controlplane-operator:dev
make install
make deploy IMG=<registry>/controlplane-operator:dev
```

### Apply sample resources
```sh
kubectl apply -k config/samples/
```

### Uninstall
```sh
kubectl delete -k config/samples/
make undeploy
make uninstall
```

## E2E tests
The e2e suite uses a Kind cluster and a shared apiserver image.

```sh
APISERVER_IMAGE=kplanedev/apiserver:v0.0.2 make test-e2e
```

Optional overrides:
- `APISERVER_REPO_DIR=/path/to/kplane-dev/apiserver` (build locally)
- `APISERVER_ARCH=amd64|arm64`

## Configuration and concepts

### ControlPlane
Represents a virtual control plane instance. Produces:
- a kubeconfig Secret
- status conditions and resolved endpoint info

### ControlPlaneEndpoint
Declares API endpoints (internal/external/join).

### ControlPlaneRegistration
Downstream attachment resource. It resolves and publishes:
- `status.resolvedEndpoint`
- `status.resolvedKubeconfigSecretRef`
- `Accepted`/`Programmed` conditions

## Contributing
Issues and PRs are welcome. For local development help, run:
```sh
make help
```

## License
Apache 2.0. See `LICENSE`.

