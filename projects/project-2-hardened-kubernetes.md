# Project 2: Hardened Container and Kubernetes Deployment

A self-directed home lab project. I took an insecure default container image, rebuilt it
securely, deployed it to a local Kubernetes cluster, hardened the deployment, added
access control and network isolation, and tested that each control actually worked.

![Security Scan](https://github.com/YOUR-USERNAME/cloud-security-homelab/actions/workflows/security-scan.yml/badge.svg)

## The problem

Default containers and default Kubernetes deployments are permissive: old base images
full of known vulnerabilities, processes running as root, no resource limits, and every
pod able to talk to every other pod. Securing the image and securing the deployment are
two separate layers, and both are needed.

## What I built

- A scan of an old image (`nginx:1.21`) to establish a baseline
- My own hardened image: newer minimal base, non-root user, health check
- A local Kubernetes cluster with kind
- A hardened Deployment: `securityContext`, read-only filesystem, dropped capabilities,
  resource limits, probes, a dedicated namespace
- RBAC with a read-only service account, verified with `kubectl auth can-i`
- A default-deny NetworkPolicy, enforced by Calico and tested with real traffic
- Kubernetes manifest scanning added to the CI pipeline

## Architecture

```
  docker/Dockerfile --build--> homelab-web:v2 (non-root, minimal base)
                                     |
                              kind load docker-image
                                     v
  kind cluster (Calico CNI)
    namespace: homelab
      |-- ServiceAccount web (token not auto-mounted)
      |-- Deployment web: non-root, read-only FS, capabilities dropped,
      |                    resource limits, readiness + liveness probes
      |-- Service web
      |-- NetworkPolicy default-deny-all (ingress + egress)
      |-- NetworkPolicy allow-web-ingress (TCP 8080 from one namespace)
      |-- Role + RoleBinding pod-reader (get, list, watch pods)

  GitHub Actions: Trivy (image) + Checkov (manifests) on every push
```

## Results

| Measure | Before | After |
|---|---|---|
| Trivy findings, `nginx:1.21` (all severities) | 921 | 0 on my image at the time of scanning |
| Trivy HIGH and CRITICAL | 266 | 0 |
| Container user | root | `nginx` (non-root), enforced in the manifest |
| Checkov, Kubernetes manifest | 69 passed, 21 failed | 88 passed, 3 failed, 1 skipped (then fixed the rest: [your final numbers]) |
| `kubectl auth can-i` as `pod-reader` | n/a | list pods: yes, delete pods: no, list secrets: no |
| NetworkPolicy test | other namespace could reach the app | other namespace timed out, allowed namespace still got the page |

The three remaining Checkov findings were handled like this:

- **Low UID:** moved from UID 101 to 10001, so it is unlikely to collide with a host user
- **No NetworkPolicy:** added default-deny plus a specific allow rule
- **Image pull policy:** skipped with a written reason, because the image exists only
  inside the local cluster and `Always` would fail to pull it

## The NetworkPolicy test

I did not trust a passing scan. Checkov was satisfied by the policy file, but kind's
default networking does not enforce NetworkPolicies, so I rebuilt the cluster with Calico
and tested with throwaway pods:

| Test | Source namespace | Result |
|---|---|---|
| Before the policy | client-bad | page returned (open by default) |
| After the policy | client-bad | timed out (blocked) |
| After the policy | client-ok | page returned (allowed) |

Same URL, same pod type, and only the policy changed.

## Skills demonstrated

- Docker image hardening: base image choice, non-root users, health checks
- Vulnerability scanning and triage with Trivy
- Kubernetes workloads: Deployments, Services, namespaces
- Pod hardening with `securityContext`, resource limits and probes
- RBAC and least privilege, verified with `kubectl auth can-i`
- Network isolation with default-deny NetworkPolicies, tested on Calico
- CI scanning of images and manifests with GitHub Actions

## Problems I hit and what they taught me

- **A typo made a permission test meaningless.** Misspelling the service account name
  made `kubectl auth can-i` return `no` for everything. A `no` only proves something
  after you have seen a `yes` from the same identity.
- **A clean scan is a snapshot.** The pipeline went red on later runs because new CVEs
  were published against the Alpine base image (including `brotli-libs` and a libexpat
  overflow). I patched with `apk upgrade`, kept the container non-root, and verified
  with Trivy.
- **A policy only counts once it blocks traffic.** Passing a scanner showed the policy
  existed, and only the before-and-after traffic test showed it was enforced.

## How to reproduce

1. Build the image: `docker build -t homelab-web:v2 docker/`
2. Create a cluster with Calico (config in `kind/kind-calico.yaml`), then install Calico
3. Load the image: `kind load docker-image homelab-web:v2 --name homelab`
4. Apply the manifests in `k8s/` (`web.yaml`, `rbac.yaml`, `networkpolicy.yaml`)
5. Scan: `docker run --rm -v ${PWD}/k8s:/k8s bridgecrew/checkov -d /k8s --framework kubernetes`
6. Test the policy with throwaway pods from two namespaces

## Limitations

- Single-node local cluster, not a real cloud environment
- The image is loaded locally, not pulled from a registry and pinned by digest
- No runtime detection (for example Falco) and no admission control (for example Kyverno
  or OPA Gatekeeper)
- Default-deny egress would need extra rules for an application that calls a database
  or an API
- A scan result of zero is true only at the time of scanning

## What I would do next

- Push the image to a registry, pin it by digest, and sign it
- Add admission policies that reject root containers and unencrypted resources
- Add runtime detection with Falco
- Add a scheduled weekly scan so new CVEs surface on a schedule
