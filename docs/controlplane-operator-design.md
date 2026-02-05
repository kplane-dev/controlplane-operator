## ControlPlane Operator Design

### Purpose
The controlplane operator defines and reconciles infrastructure-focused
resources that represent virtual control planes (etcd + apiserver) and their
management-plane defaults. It does not run workload controllers or scheduling.
This separation enables independent upgrades, migrations, and service choices.

### Scope
- Create and reconcile control-plane infrastructure for virtual clusters.
- Publish endpoint + kubeconfig material for downstream services to consume.
- Apply management-plane defaults via classes.
- Avoid coupling to multi-cluster controller/scheduler operators.
- Support migration paths (virtual → dedicated) without changing service repos.

### Repo Boundaries
- This repo owns control-plane infrastructure and its CRDs.
- A scheduler repo watches registrations to start per-cluster scheduling.
- A controller-manager repo watches registrations to start per-cluster control
  loops (the standard kube-controller-manager behavior).
- Workload agents/operators can also watch registrations if needed.

### Parts and Responsibilities (High Level)
- Controlplane operator: creates control-plane infra, endpoints, kubeconfig.
- Endpoint providers: publish DNS/LB/gateway addresses when needed.
- Registration controller: resolves control-plane access for service consumers.
- Downstream services: consume registration output to bootstrap controllers,
  scheduling, or workloads.

### Core Resources

#### ControlPlane
Represents a virtual control plane instance.
- Inputs:
  - `spec.mode`: `Virtual` (current) or `Dedicated` (future).
  - `spec.classRef`: defaults/policy via `ControlPlaneClass`.
  - `spec.endpointPolicy` (future): describes how endpoints are allocated.
  - `spec.virtual.clusterPath`: etcd path segment for virtual cluster data.
- Outputs:
  - `status.endpoints` (future): list of resolved endpoints (internal/external/join).
  - `status.kubeconfigSecretRef`: secret containing kubeconfig for clients.
  - `status.phase` (future): `Provisioning`, `Ready`, `Migrating`, `Failed`.
  - `status.migration` (future): detail on virtual → dedicated transitions.

#### ControlPlaneClass
Defines defaults and policy for control plane instances.
- Examples:
  - Default deletion policy (`Retain` or `Destroy`).
  - Default auth posture and addons bundle selection.

#### ControlPlaneEndpoint
Declares a single API endpoint variant (internal/external/join as needed).
- Designed for one addressable endpoint tuple.
- Can be attached to a ControlPlane by reference (now) or selected by policy
  (future) if a ControlPlane may have multiple endpoints.
- `spec.endpoint`, `spec.externalEndpoint`, `spec.joinEndpoint`
- `status.*` mirrors observed endpoints if a separate provider updates them.

### Integration Resources (New)

#### ControlPlaneRegistration
Represents desired attachment of services (controllers, scheduler, workloads)
to a control plane, independent of the control-plane infrastructure.
- Inputs:
  - `spec.controlPlaneRef`: reference to `ControlPlane`.
  - `spec.endpointRef`: optional override to a `ControlPlaneEndpoint` (or in
    future, a selector when multiple endpoints exist).
  - `spec.kubeconfigSecretRef`: optional secret for clients.
  - `spec.services`: list of service intents (e.g. `controllers`, `scheduler`,
    `workloads`).
  - `spec.mode`: `Shared` or `Dedicated` (service-level separation).
- Outputs:
  - `status.ready`: indicates registration resolution is usable.
  - `status.resolvedEndpoint`: endpoint chosen after resolution.
  - `status.resolvedKubeconfigSecretRef`: final secret ref for clients.
  - `status.conditions`: validation and resolution status.

### Reconciliation Responsibilities

#### ControlPlane controller (in this repo)
- Ensures management namespace exists.
- Resolves `ControlPlaneEndpoint` and produces `status.endpoint`.
- Generates and stores kubeconfig secret.
- Applies deletion policy (retain/destroy data in etcd).

#### ControlPlaneEndpoint provider (external or manual)
- Populates endpoints when needed (gateway, load balancer, etc).
- May set `status.*` if observation differs from spec.

#### ControlPlaneRegistration controller (in this repo)
- Resolves references:
  - Uses `spec.kubeconfigSecretRef` if provided.
  - Else, uses `ControlPlane.status.kubeconfigSecretRef`.
  - Uses `spec.endpointRef` if provided.
  - Else, uses `ControlPlane.status.endpoints` (or current single endpoint).
- Publishes `status.resolved*` fields.
- Leaves actual service bootstrapping to external operators.

### End-to-End Flow
1) User creates `ControlPlaneEndpoint` (or a provider populates it).
2) User creates `ControlPlane` with `endpointRef` and optional `classRef`.
3) Controlplane operator:
   - Bootstraps virtual control plane data.
   - Writes kubeconfig Secret.
   - Sets `ControlPlane.status.endpoint` and secret ref.
4) Management-plane operator creates `ControlPlaneRegistration`
   (or user creates it directly).
5) Downstream repos watch `ControlPlaneRegistration` and start per-cluster
   services using resolved endpoint + kubeconfig.

### Defaults and Policy
- `ControlPlaneClass` provides management defaults (deletion policy, auth,
  addons).
- The management-plane operator can auto-create `ControlPlaneRegistration`
  objects based on class defaults (e.g. enable `controllers` + `scheduler`).

### Migrations and Upgrades
- `ControlPlane.spec.mode` allows virtual or dedicated control planes.
- Migration is modeled as:
  1) Provision dedicated control plane alongside the virtual control plane.
  2) Ensure data plane readiness (API server healthy, endpoints stable).
  3) Publish new endpoint + kubeconfig in `ControlPlane.status`.
  4) Update `ControlPlaneRegistration` to point at the new endpoint/secret.
  5) Downstream services reconnect and reconcile to the new control plane.
  6) Decommission virtual control plane data after drain/verification.
- Downstream services are insulated because they only follow registrations.

### Downstream Consumption
Downstream operators (scheduler, multicluster controller manager, workload
agents) should watch `ControlPlaneRegistration` only.
- They do not need to watch `ControlPlane` or `ControlPlaneEndpoint` directly.
- They consume `status.resolvedEndpoint` +
  `status.resolvedKubeconfigSecretRef`.

### Naming and Ownership
- `ControlPlane` owns kubeconfig Secret and management namespace.
- `ControlPlaneRegistration` is owned by the management plane (or user), and is
  not owned by downstream service operators.

### CRD Sketches

#### ControlPlane (existing)
```yaml
apiVersion: controlplane.kplane.dev/v1alpha1
kind: ControlPlane
metadata:
  name: example
spec:
  classRef:
    name: default
  mode: Virtual
  endpointRef:
    name: example-endpoint
  virtual:
    clusterPath: example
```

#### ControlPlaneEndpoint (existing)
```yaml
apiVersion: controlplane.kplane.dev/v1alpha1
kind: ControlPlaneEndpoint
metadata:
  name: example-endpoint
spec:
  endpoint: https://shared.kplane.example/clusters/example/control-plane
  externalEndpoint: https://example.kplane.example
  joinEndpoint: https://example.join.kplane.example/clusters/example/control-plane
```

#### ControlPlaneClass (existing)
```yaml
apiVersion: controlplane.kplane.dev/v1alpha1
kind: ControlPlaneClass
metadata:
  name: default
spec:
  deletionPolicy: Retain
  auth:
    model: v0
    defaultRole: cluster-admin
  addons:
    - starter
```

#### ControlPlaneRegistration (new)
```yaml
apiVersion: controlplane.kplane.dev/v1alpha1
kind: ControlPlaneRegistration
metadata:
  name: example
spec:
  controlPlaneRef:
    name: example
  services:
    - controllers
    - scheduler
  mode: Shared
  kubeconfigSecretRef:
    name: controlplane-example-kubeconfig
    namespace: kplane-cp-example
```

### Phased Rollout
1) Add `ControlPlaneRegistration` API and controller in this repo.
2) Management-plane operator auto-creates registrations by default.
3) Downstream operators switch to watching registrations.
4) Optionally remove direct endpoint watching in downstream operators.

### Open Questions
- Should `ControlPlaneRegistration` be namespaced to allow multi-tenant intent?
- Should `services` be enum or string list with validation?
- Do we need a separate `ControlPlaneServiceClass` for shared/dedicated defaults?
