# GitOps with Flux on the `bigboy` AKS Cluster

This runbook covers the GitOps path for deploying `rust_oauth2_server` to the
production AKS cluster (`bigboy`, resource group `nekoc`, location `centralus`).
It replaces the historical "apply with raw `kubectl`" flow documented in
`docs/observability.md` §9.

Flux on `bigboy` is installed as the **Azure-managed** extension
(`microsoft.flux`) — configurations are provisioned through the Azure CLI
(`az k8s-configuration flux create`) rather than by applying FluxCD CRs
directly with `kubectl`. The extension still runs the standard upstream
`source-controller`, `kustomize-controller`, and `notification-controller`,
plus `image-reflector-controller` and `image-automation-controller` for
image automation when we opt in.

## 1. Repository layout

```
k8s/
├── base/                              # vendor-neutral base manifests
├── overlays/
│   ├── production/                    # production overlay (Flux reconciles this)
│   └── production-distributed/        # distributed variant (Redis cache + rate-limit)
└── flux/
    └── clusters/
        └── bigboy/
            ├── kustomization.yaml     # root kustomize, resources: [oauth2-server.yaml]
            └── oauth2-server.yaml     # Flux Kustomization CR pointing at overlays/production
```

The Azure `FluxConfig` reconciles `k8s/flux/clusters/bigboy/` on every sync.
The `Kustomization` CR it finds there points Flux at
`k8s/overlays/production`, which is what actually renders into the cluster.

## 2. One-time provisioning

Run this from a workstation with `az login` already done and the AKS
`bigboy` context kubeconfig on hand. The command creates (or upserts) a
`FluxConfig` in the `flux-system` namespace.

```bash
az k8s-configuration flux create \
  --resource-group nekoc \
  --cluster-name bigboy \
  --cluster-type managedClusters \
  --name oauth2-server \
  --namespace flux-system \
  --scope cluster \
  --source-kind git \
  --url https://github.com/ianlintner/rust-oauth2-server.git \
  --branch main \
  --interval 1m \
  --kustomization \
      name=oauth2-server \
      path=k8s/flux/clusters/bigboy \
      prune=true \
      sync_interval=1m \
      retry_interval=5m \
      timeout=10m
```

Notes:

- The `FluxConfig` `name` (`oauth2-server`) becomes the name of the
  generated `GitRepository` in `flux-system`. The inner `Kustomization`
  CR at `k8s/flux/clusters/bigboy/oauth2-server.yaml` references that
  name via `spec.sourceRef.name: oauth2-server` — keep the two in sync.
- `scope=cluster` gives Flux permission to create resources outside
  `flux-system`. The overlay targets `namespace: default`.
- For a private repo, add `--https-user <user> --https-key <PAT>`.
  Public repos (like this one today) need no credentials.

## 3. Verifying the initial sync

```bash
kubectl -n flux-system get fluxconfig oauth2-server -o yaml
kubectl -n flux-system get gitrepository,kustomization | grep oauth2-server
kubectl -n default rollout status deploy/oauth2-server --timeout=5m
```

Expected: the `FluxConfig` reports `complianceState: Compliant`, the
`Kustomization` shows `READY=True`, and the deployment rolls out the image
tag pinned in `k8s/overlays/production/kustomization.yaml`.

## 4. Release workflow + image tag bumps

The release workflow (`.github/workflows/release.yml`) bumps
`Cargo.toml` / `Cargo.lock`, tags `vX.Y.Z`, and publishes multi-arch
images to GHCR and Docker Hub. It does **not** edit the Kubernetes
overlays — that is a separate step so a release is never tangled up with
a production rollout.

After a release completes:

1. Open a PR that updates
   `k8s/overlays/production/kustomization.yaml` (and the distributed
   variant, if applicable) to pin `images[].newTag` to the new version.
2. Optionally bump `IMAGE_SHA` in
   `k8s/overlays/production/observability-patch.yaml` to the matching
   commit SHA so `service.version` in traces lines up with the build.
3. Merge. Flux reconciles within one sync interval (`1m` above) and
   rolls the deployment.

This keeps prod rollouts as reviewable PRs with full history, at the
cost of one extra PR per release.

## 5. Image automation (enabled)

Flux's `ImageRepository` / `ImagePolicy` / `ImageUpdateAutomation` CRs
automate step 4 by watching Docker Hub for new semver tags and committing
overlay tag bumps directly to `main`. The CRs live in
`k8s/flux/clusters/bigboy/image-automation.yaml` and are reconciled by the
same root kustomization as `oauth2-server.yaml`.

Moving pieces:

- **`GitRepository/oauth2-server-write`** — a second `GitRepository` in
  `flux-system` that carries HTTPS credentials so the
  `image-automation-controller` can push commits. The Azure-managed
  `GitRepository` (provisioned by the `FluxConfig`) is read-only and
  cannot be reused for writes.
- **`ImageRepository/oauth2-server`** — polls `docker.io/ianlintner068/oauth2-server`
  every 5m.
- **`ImagePolicy/oauth2-server`** — selects the highest semver tag matching
  `^[0-9]+\.[0-9]+\.[0-9]+$`. Pre-release variants (`-mongo`, `-mongo-only`,
  `sha-*`) are filtered out so they never get promoted to production.
- **`ImageUpdateAutomation/oauth2-server`** — scans
  `k8s/overlays/production/kustomization.yaml` for the Setters marker
  `# {"$imagepolicy": "flux-system:oauth2-server:tag"}` and commits
  `chore(flux): bump oauth2-server image to <tag>` to `main` when the
  policy picks a newer version.

### 5.1 One-time Secret provisioning

The write path needs a Git PAT. Create it out-of-band — the Secret is
intentionally not committed to this repo:

```bash
kubectl -n flux-system create secret generic oauth2-server-git-auth \
  --from-literal=username=x-access-token \
  --from-literal=password="$GITHUB_TOKEN"
```

`GITHUB_TOKEN` must be a classic or fine-grained PAT with `repo` (or
`contents: write`) scope on `ianlintner/rust-oauth2-server`. Rotate by
replacing the Secret; no controller restart required.

### 5.2 Branch protection

Because the automation pushes directly to `main`, `main` must either:

- allow the PAT identity (`x-access-token`) to bypass branch protection, or
- have no protection rule requiring PR review.

If you want PR review on automated bumps, change `push.branch` in the
`ImageUpdateAutomation` CR to a dedicated branch (e.g. `flux-image-updates`)
and add a GitHub auto-merge workflow.

### 5.3 Opting a new overlay into automation

Add the Setters marker next to the `newTag` line in the overlay's
`kustomization.yaml`:

```yaml
images:
  - name: docker.io/ianlintner068/oauth2-server
    newTag: 0.7.0 # {"$imagepolicy": "flux-system:oauth2-server:tag"}
```

The `production-distributed` overlay is not wired yet; add the marker
there if/when that variant starts tracking releases in lockstep.

## 6. Rollback

Because the overlay is a Git artifact, rollback is a `git revert` of the
PR that bumped the tag. Flux reconciles the revert the same way it
reconciled the bump.

For emergency rollback when you cannot wait for a PR, suspend the
`FluxConfig` with:

```bash
az k8s-configuration flux update \
  --resource-group nekoc --cluster-name bigboy \
  --cluster-type managedClusters --name oauth2-server \
  --suspend true
```

then apply a `kubectl rollout undo deploy/oauth2-server` directly. Resume
Flux (`--suspend false`) once the repo matches the intended state again,
otherwise the next reconcile will re-apply the broken version.
