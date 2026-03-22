# Kplane Sharding and Autoscaling Design (Draft)

## Summary

This document proposes an idiomatic Kubernetes design for sharding virtual control planes across multiple shared cores, where each core is a shared `{apiserver + etcd}` stack and each tenant control plane is routed by URL path.

The design builds on current `controlplane-operator` behavior:

- A `ControlPlane` already models one virtual control plane.
- `ControlPlane.spec.virtual.clusterPath` models `/clusters/<clusterPath>/control-plane`.
- `ControlPlaneEndpoint` already represents the API endpoint tuple.
- `ControlPlaneRegistration` is already the downstream integration contract.

The missing pieces are placement, shard capacity tracking, and autoscaling policy.

## Problem Statement

Kplane can host many virtual control planes on one shared API server and etcd stack via path-based routing. As adoption grows, we need to:

- Spread control planes across multiple shared cores.
- Keep endpoint ownership deterministic and stable.
- Place control planes based on policy and capacity.
- Scale shard fleet size based on measured usage and policy headroom.

## Goals

- Horizontal scale of shared apiserver/etcd cores.
- Deterministic route and ownership for each virtual control plane.
- Policy-aware placement (tenant, class, SLA tier).
- Kubernetes-native APIs and reconciliation flow.
- Safe rebalancing posture for v1 (no automatic migration).

## Non-goals (v1)

- Live migration of a control plane between shards.
- Cross-region traffic steering.
- Fine-grained per-request load shaping across shards.
- Full dedicated control plane provisioning/orchestration.

## Current State (What Exists Today)

### Virtual control planes are path-based

The operator ensures virtual endpoints include the canonical path:

- `/clusters/<clusterPath>/control-plane`
- `clusterPath` defaults to `ControlPlane.metadata.name`
- endpoint rewriting is performed in reconcile when needed

### Endpoint resolution contract is already clear

- `ControlPlaneEndpoint` contains internal/external/join endpoints.
- `ControlPlane.status.endpoint` is published for the resolved endpoint.
- `ControlPlaneRegistration.status.resolvedEndpoint` is the consumption point for downstream controllers/schedulers.

### Shared core assumptions already exist

E2E and controller flow already assume a shared apiserver service backing many control planes with path segmentation, which maps naturally to the shard model in this document.

### Dedicated mode already exists in API shape

`ControlPlane.spec.mode` already allows `Virtual` and `Dedicated`. Current sharding work should focus on `Virtual`, but must not block future `Dedicated` implementations.

## Flexibility for Future Dedicated Stacks

Keep this simple and explicit:

- `ControlPlane.spec.mode` is the top-level switch.
- Shard placement/routing/autoscaling only apply when `mode=Virtual`.
- `mode=Dedicated` bypasses shard APIs (`ControlPlaneShard`, `shardRef`, route synthesis).
- `ControlPlaneRegistration` remains the stable downstream contract in both modes.

This gives us one consumer contract (`ControlPlaneRegistration`) and two infrastructure backends (shared virtual now, dedicated later) without over-designing a universal scheduler up front.

## Sharding Model

## 1) `ControlPlaneShard` (new CRD)

`ControlPlaneShard` represents one shared core failure domain and scheduling target.

```yaml
apiVersion: controlplane.kplane.dev/v1alpha1
kind: ControlPlaneShard
metadata:
  name: shard-a
spec:
  capacity:
    maxControlPlanes: 500
    cpuLimit: "8"
    memoryLimit: "16Gi"
  placement:
    allowedClasses:
      - standard
      - bronze
    tenantSelector:
      matchLabels:
        tier: standard
  routeBase:
    externalURL: https://api.kplane.dev/shards/shard-a
    internalURL: https://kplane-apiserver.shard-a.svc.cluster.local:6443
status:
  phase: Ready
  usage:
    controlPlanes: 312
    cpu: "5.2"
    memory: "9.4Gi"
  conditions:
    - type: Ready
      status: "True"
```

Notes:

- `spec.routeBase` is the shard base URL, not a full control plane URL.
- Final control plane endpoint remains path-based and deterministic.
- Status usage is controller-populated and becomes autoscaler input.

## 2) Placement ownership (`ControlPlane.spec.shardRef`, new optional field)

`ControlPlane.spec.shardRef.name` declares shard ownership once selected.

Placement rules:

- Set once at creation time (or first reconcile if unset).
- Immutable in v1 unless an explicit migration workflow is introduced.
- If constraints cannot be satisfied, publish a `PlacementPending` condition.
- Valid only for `ControlPlane.spec.mode=Virtual`.

## 3) Routing representation

The external contract remains:

- `ControlPlane.status.endpoint` for clients.
- `ControlPlaneRegistration.status.resolvedEndpoint` for downstream operators.

Route ownership should live on `ControlPlaneEndpoint` in early phases, since that resource already models endpoint intent and internal/external variants.

Suggested direction:

- Keep `ControlPlaneEndpoint` as the source of truth for routing intent.
- Reconcile `HTTPRoute` from `ControlPlaneEndpoint + ControlPlane + ControlPlaneShard`.
- Continue publishing resolved endpoint on `ControlPlane.status.endpoint`.
- Keep `ControlPlaneRoute` as a future-only option if endpoint ownership and route programming need separate RBAC/lifecycle boundaries.

Future optional split (`ControlPlaneRoute`) if needed:

```yaml
apiVersion: controlplane.kplane.dev/v1alpha1
kind: ControlPlaneRoute
metadata:
  name: cp-123
spec:
  controlPlaneRef:
    name: cp-123
  shardRef:
    name: shard-a
  path: /clusters/cp-123/control-plane
status:
  ready: true
```

`ControlPlaneRoute` is not required for initial phases; it is only introduced if route ownership must be decoupled from endpoint ownership.

## Controller Architecture

## Placement Controller (in `controlplane-operator`)

Responsibilities:

- Watch `ControlPlane`, `ControlPlaneShard`, and policy resources.
- Select shard based on class/tenant policy and free capacity.
- Write `ControlPlane.spec.shardRef` (or condition failure).
- Never auto-reassign in v1.

Suggested selection algorithm (deterministic):

1. Filter shards by readiness and selector compatibility.
2. Filter by hard capacity limits.
3. Sort by score (most free headroom, then lexical name tie-breaker).
4. Pick first and persist shard ref.

## Route Controller (in `controlplane-operator`)

Responsibilities:

- Build canonical endpoint from:
  - shard route base
  - `ControlPlane.spec.virtual.clusterPath`
- Publish endpoint to `ControlPlane.status.endpoint`.
- Optionally reconcile `ControlPlaneRoute`.
- Keep `ControlPlaneRegistration` contract unchanged.
- Skip shard-based route synthesis for `mode=Dedicated` (provider-owned endpoint).

Endpoint shape:

- `<shard-route-base>/clusters/<clusterPath>/control-plane`

## Shard Usage Controller

Responsibilities:

- Aggregate per-shard usage:
  - control plane count
  - CPU/memory utilization
  - optionally request rate and latency
- Write to `ControlPlaneShard.status.usage`.

This can consume metrics from standard Kubernetes APIs (metrics-server / custom metrics) and shard-local telemetry.

## Shard Autoscaler

Responsibilities:

- Watch `ControlPlaneShard.status.usage`, policy, and pending placements.
- Scale shard backing workloads (Deployment/StatefulSet/HPA) or create new shards.
- Maintain target headroom.

Inputs:

- `status.usage.controlPlanes`
- `status.usage.cpu`, `status.usage.memory`
- policy constraints (tenant density, class-specific limits)
- pending placement queue depth

Outputs:

- Increase shard capacity (vertical/horizontal, implementation-dependent).
- Create additional shard objects and backing infra when fleet is saturated.

## Intelligent Placement and Capacity Model

Control plane count alone is not enough for good placement. A shard can host many low-traffic control planes or fewer high-traffic ones. Placement should therefore use projected resource usage.

### Capacity inputs

At minimum, track these per shard:

- `cpuUsed`, `memUsed`
- `requestRate` (apiserver requests/sec)
- `controlPlaneCount`
- optional SLO signals: `p95Latency`, `errorRate`

At minimum, estimate these per control plane:

- `cpuEstimate`
- `memEstimate`
- `requestRateEstimate`

In v1, estimates can be class-based defaults (small/medium/large profile). Later, they can be learned from observed historical usage.

### Admission thresholds

Use both a target headroom and a hard limit:

- target utilization: for example 80% of CPU/memory/QPS
- hard stop: for example 90%

A candidate placement is rejected if projected usage crosses hard limits.

### Placement algorithm (deterministic)

1. **Filter eligible shards** by:
   - class/tier compatibility
   - shard readiness
   - policy constraints (tenant density, anti-affinity, etc)
2. **Project usage** for each eligible shard:
   - `cpuProjected = cpuUsed + cp.cpuEstimate`
   - `memProjected = memUsed + cp.memEstimate`
   - `qpsProjected = requestRate + cp.requestRateEstimate`
3. **Reject** shards where any projected metric exceeds hard limit.
4. **Score** remaining shards by post-placement headroom, with deterministic tie-break:
   - higher headroom preferred
   - lexical shard name as final tie-breaker
5. **Select** top score and publish placement.
6. If none are valid, mark `PlacementPending` and trigger autoscaler.

### Example score function

`score = wCpu*cpuHeadroom + wMem*memHeadroom + wQps*qpsHeadroom - penalties`

Where penalties can include:

- tenant concentration penalty
- SLO pressure penalty (latency/error budget pressure)

Keep v1 simple with static weights and no predictive forecasting.

### Autoscaler reaction loop

When pending placements exist or average shard headroom drops below target:

- scale up existing shard backing workloads when possible
- create additional shards when vertical scale is exhausted or policy requires separation

Placement retries after shard capacity changes are observed.

### Practical rollout

- **v1:** count + cpu/memory + class-based size profiles
- **v2:** add request-rate-aware placement
- **v3:** add SLO-aware penalties and optional predictive placement

## Policy Model

Reuse existing class-centric design by extending `ControlPlaneClass` with placement defaults, or add a dedicated `ShardPolicy` CRD.

Recommended v1 shape:

- Keep operator policy simple and explicit.
- Prefer class-driven defaults (already idiomatic in this repo).
- Use class as the primary selector for shared vs dedicated infrastructure tier.

### Class-driven infrastructure tier

`ControlPlaneClass` should be the main policy surface that indicates whether a control plane belongs on:

- a shared/sharded virtual tier ("free"/pooled),
- or a dedicated tier (isolated apiserver stack).

Suggested shape (additive to existing class spec):

```yaml
apiVersion: controlplane.kplane.dev/v1alpha1
kind: ControlPlaneClass
metadata:
  name: free
spec:
  infrastructure:
    tier: Shared
    shardPool: standard
---
apiVersion: controlplane.kplane.dev/v1alpha1
kind: ControlPlaneClass
metadata:
  name: enterprise-dedicated
spec:
  infrastructure:
    tier: Dedicated
```

Resolution order (keep this simple):

1. `ControlPlane.spec.mode` explicitly set by user wins.
2. Else infer mode from `ControlPlaneClass.spec.infrastructure.tier`.
3. Else default to `Virtual` (current behavior).

Operational effect:

- `tier=Shared` maps to shard placement (`ControlPlaneShard`, `shardRef`, autoscaling).
- `tier=Dedicated` maps to dedicated provider flow (no shard placement).

Example policy dimensions:

- max control planes per shard
- minimum free headroom percentage
- allowed shard pools for class/tier
- anti-affinity hints by tenant label
- class-based control plane size profile (small/medium/large) for initial cost estimation

## Gateway API Integration

Use Gateway API to avoid ingress-vendor coupling:

- One or more `Gateway` resources front shard backends.
- Route controller reconciles `HTTPRoute` from control plane route ownership.
- `ControlPlane.status.endpoint` is derived from the Gateway listener hostname + canonical path.

Why this is idiomatic:

- clear separation between desired routing intent and data-plane implementation
- portable across Envoy/Kong/Istio-backed Gateway controllers
- standard Kubernetes reconciliation and status propagation patterns

## Data and Failure Semantics

- Each shard is a failure domain.
- Placement excludes shards that are not `Ready`.
- Existing control planes on unhealthy shards are not migrated automatically in v1.
- Recovery is operational (restart/repair shard); clients keep stable endpoint paths.

For deletion:

- Existing `Retain`/`Destroy` policy semantics on `ControlPlane` remain unchanged.
- Shard lifecycle does not implicitly delete tenant control plane data.

## Backward Compatibility

This design is additive:

- Existing `ControlPlaneEndpoint`-based flow continues to work.
- Existing `ControlPlaneRegistration` consumers require no changes.
- Sharding can be introduced behind optional fields and new controllers.
- Future dedicated providers can reuse the same `ControlPlane` and `ControlPlaneRegistration` API contracts.

Compatibility strategy:

1. If `spec.shardRef` is unset and no shard controller is enabled, current endpoint behavior remains.
2. If shard controller is enabled, it fills shard ownership and endpoint resolution.
3. Route controller continues to write the same status fields consumed today.
4. If `spec.mode=Dedicated`, endpoint resolution comes from dedicated provider flow, not shard flow.

## Phased Rollout

### Phase 1: Endpoint and routing foundation (Gateway API aligned)

Goal: make routing ownership explicit and correct for both internal and external access, regardless of whether there is one shared stack or many horizontally scaled stacks.

- Align `ControlPlaneEndpoint` semantics to Gateway API concepts:
  - listener/hostname + path ownership
  - internal and external endpoint variants
- Add route reconciliation from `ControlPlaneEndpoint` intent to `HTTPRoute`.
- Ensure `ControlPlane.status.endpoint` is derived from programmed Gateway route state.
- Keep consumer contract unchanged via `ControlPlaneRegistration.status.resolvedEndpoint`.
- Validate deterministic routing behavior:
  - `/clusters/<clusterPath>/control-plane` always resolves to the intended apiserver backend
  - internal and external endpoints point to the same logical control plane

### Phase 2: Shard-aware scheduling

Goal: schedule control planes efficiently across shared stacks while preserving stable ownership.

- Add `ControlPlaneShard` inventory and readiness/usage status.
- Introduce placement intent + resolved placement state (manual pin and auto modes).
- Implement deterministic shard selection (policy + capacity filters and tie-break).
- Publish placement conditions/events so operators can explain why a control plane was or was not placed.
- Keep v1 placement sticky (no automatic migration/rebalance).

### Phase 3: Capacity-aware placement and autoscaling

Goal: use real resource/load signals to decide when to spread control planes further and when to add capacity.

- Add usage aggregation per shard (CPU, memory, request rate, control plane count).
- Use projected post-placement usage in scheduling decisions.
- Add autoscaler loop:
  - scale shard backing workloads where possible
  - create additional shards when fleet headroom is exhausted
- Trigger placement retries when new capacity becomes ready.

### Phase 4: Dedicated tier integration (without changing consumer APIs)

Goal: support premium/isolated control planes while preserving the same downstream contract.

- Drive shared vs dedicated placement from `ControlPlaneClass` tier policy.
- Route `mode=Dedicated` control planes through dedicated provider flow (no shard scheduler path).
- Keep endpoint publication and `ControlPlaneRegistration` behavior identical for consumers.

### Future enhancements

- Controlled migration workflow (explicit action, not automatic rebalance).
- More advanced placement objectives (latency/affinity/cost).
- Predictive scaling and admission control based on SLO trends.

## Open Questions

- Is `ControlPlaneEndpoint` sufficient as long-term route ownership, or do we later need a separate `ControlPlaneRoute` for independent ownership/RBAC boundaries?
- Should shard policy live in `ControlPlaneClass` (fewer APIs) or a dedicated `ShardPolicy` CRD (stronger separation)?
- Which usage metrics are required for v1 autoscaling decisions vs. optional observability-only metrics?
- Do we require one Gateway per shard, or one shared Gateway with per-shard backends?

## Recommended v1 Decision Set

To stay close to current implementation and reduce risk:

- Keep `ControlPlane.status.endpoint` as the external API contract.
- Start with Gateway API-aligned endpoint and route ownership.
- Keep route programming deterministic for both internal and external endpoints.
- Introduce shard inventory and placement immediately after routing foundation is stable.
- Make placement sticky and non-migratory in v1.
- Add autoscaling only after usage telemetry is reliable.
- Drive shared-vs-dedicated intent primarily from `ControlPlaneClass`; allow explicit `ControlPlane.spec.mode` override.
