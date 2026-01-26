## Multi-Cluster Controller Manager Design

### Summary
Create a new repo that runs a drop-in Kubernetes controller manager for many
downstream control planes by starting one kube-controller-manager instance per
registered cluster inside a single pod (initially 1 replica). Use
ControlPlaneEndpoint as the cluster registry and optionally shard across pods
using multi-cluster runtime sharding.

### Goals
- Drop-in behavior: run the standard Kubernetes controller set without
  re-implementing individual controllers.
- Multi-cluster: dynamically start/stop per-cluster controller-manager loops
  as endpoints are added/removed/updated.
- Shardable: align with the sharding work so we can scale horizontally later.
- Start with 1 replica to validate correctness and operational stability.

### Non-Goals
- Rewriting individual controllers or changing their behavior.
- Multi-tenant isolation beyond per-cluster separation in-process.
- Full HA/scale from day one.

### Dependencies
- ControlPlaneEndpoint CRD (source of per-cluster endpoint + auth material).
- Multi-cluster runtime sharding:
  PR 74: ✨ Multi cluster controller sharding
  https://github.com/kplane-dev/multicluster-runtime/pull/74

### Proposed Repo
`kplane-dev/multicluster-controller-manager`

### Provider Package (Shared)
Create a custom multi-cluster runtime provider in `pkg/` (within the new repo) so
other services can reuse the dynamic cluster discovery:

- Package location: `pkg/provider/controlplaneendpoint`
- Purpose: watch `ControlPlaneEndpoint` objects and emit cluster registrations
  for multicluster-runtime.
- Reuse: other services can import the provider to dynamically discover clusters
  without duplicating registry logic.

### High-Level Architecture
1) Cluster registry watches ControlPlaneEndpoint objects.
2) For each endpoint in the active shard:
   - Build rest.Config (endpoint + auth).
   - Start a kube-controller-manager instance with that config.
3) When an endpoint is removed or moved out of shard:
   - Stop and clean up the per-cluster manager.

### Cluster Registry
- Watch `ControlPlaneEndpoint` (and possibly `ControlPlane` for metadata).
- Index by endpoint name for quick lookups.
- Maintain an in-memory map:
  - key: endpoint name
  - value: manager instance + cancel func + last applied config

### Per-Cluster Manager Lifecycle
- Start:
  - Construct kube-controller-manager config from per-cluster kubeconfig.
  - Use a dedicated identity for metrics/leader election per cluster.
- Stop:
  - Cancel context + wait for controller-manager to exit.

### Sharding (Phase 2)
- Use multi-cluster runtime sharding filter from PR 74.
- Only create managers for endpoints that match the shard selector.
- Scale horizontally by increasing replicas with different shard IDs.

### Config / Flags
- Keep kube-controller-manager flags for compatibility.
- Add multicluster flags:
  - `--cluster-source=controlplaneendpoint`
  - `--cluster-namespace-scope` (optional)
  - `--cluster-shard-id` (optional, when sharding enabled)
  - `--cluster-kubeconfig-secret-template`

### Security / Auth
- Recommend using per-cluster kubeconfig stored in Secret referenced by
  ControlPlaneEndpoint.
- Root controller uses its own SA only to read endpoints + secrets.

### Observability
- Per-cluster metrics labels: `cluster=<name>`
- Health endpoints include per-cluster readiness summaries.

### Rollout Plan
1) MVP: 1 pod, 1 replica, dynamic per-cluster managers.
2) Enable sharding (PR 74) but still run with 1 replica.
3) Scale replicas and add shard labels to endpoints.

### Open Questions
- Which controllers are strictly required for virtual control planes?
- Do we need per-cluster leader election when only one process runs managers?
- How should we handle transient endpoint changes (backoff/retry strategy)?
