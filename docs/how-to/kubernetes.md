# Set up Kubernetes credentials

The Kubernetes provider creates a per-session ServiceAccount and requests a bounded
token from the Kubernetes API outside the sandbox. It writes the token to a minimal
kubeconfig mounted read-only in the session. When the session ends, corral removes the
ServiceAccount and related resources. `corral gc` can remove resources left by a crashed
session.

Choose who should manage the ServiceAccount's RBAC:

- [`managed`](#managed-mode) lets corral create bindings from config. The host
  identity needs the cluster permissions required to create those bindings.
- [`preProvisioned`](#preprovisioned-mode) uses bindings created by an administrator.
  The host identity needs `edit` only in a dedicated corral namespace.

Both modes require a working host kubeconfig and context. The host credential
stays outside the sandbox.

## Managed mode

Managed mode is the default. This minimal config creates the session ServiceAccount
in namespace `corral` and grants it the cluster-wide `view` ClusterRole:

```yaml
providers:
  kubernetes:
    enabled: true
```

To restrict or change the grant, set `permissions`. This example grants `edit` only
in namespaces labeled for the platform team:

```yaml
providers:
  kubernetes:
    enabled: true
    permissions:
      - namespaceSelector:
          matchLabels:
            team: platform
        clusterRole: edit
```

A permission must choose one scope (`clusterWide: true` or `namespaceSelector`)
and one role (`clusterRole` or `role`). A cluster-wide grant requires a
`clusterRole`. See [`providers.kubernetes`](../reference/config.md#providerskubernetes)
for every field and selector operator.

Because `edit` grants write access, this example adds a warning to the launch banner.
Review the grant, then confirm the launch.

### Host RBAC for managed mode

The host identity that runs corral needs these permissions:

| Operation | Verbs | Resource |
| --- | --- | --- |
| Create and remove the session ServiceAccount | `create`, `delete`, `list` | `serviceaccounts` |
| Request the token | `create` | `serviceaccounts/token` |
| Check the ServiceAccount namespace | `get` | `namespaces` |
| Create the ServiceAccount namespace if absent | `create` | `namespaces` |
| Resolve a `namespaceSelector` | `list` | `namespaces` |
| Manage cluster-wide grants | `create`, `get`, `delete`, `list` | `clusterrolebindings` |
| Manage namespaced grants | `create`, `get`, `delete`, `list` | `rolebindings` |

Kubernetes also prevents privilege escalation through bindings. The host identity
must hold the permissions being granted or have `bind` permission on the referenced
Role or ClusterRole. The `escalate` verb applies when creating or updating roles;
corral creates bindings, not roles. Pointing `serviceAccountNamespace` at an existing
namespace removes the need for `create` on namespaces; managed mode still requires
`get`.

If you set `providers.kubernetes.as`, corral makes its setup calls as that user, like
`kubectl --as`. The base identity needs impersonation permission, but this setting does
not change the ServiceAccount named in the session token.

## PreProvisioned mode

Use `preProvisioned` when an administrator should own the RBAC and developers
should hold only the stock namespace-scoped `edit` role in a dedicated corral
namespace.

At launch, corral:

1. checks the configured namespace when permitted;
2. creates a per-session ServiceAccount and an empty revocation Secret there;
3. binds the token to that Secret through `TokenRequest`;
4. deletes both resources at session end.

Session resource names follow `corral-<user>-<session>`, which helps identify an orphan
before using `corral gc`. Deleting either resource invalidates the token before its
normal expiry.

### Prepare the cluster once

An administrator must:

1. Create a dedicated namespace, such as `corral-team-a`, with no other workloads.
2. In each target namespace, bind the group
   `system:serviceaccounts:corral-team-a` to the role sessions should receive. Kubernetes
   automatically places every ServiceAccount from `corral-team-a` in this group, so each
   per-session identity receives the binding.
3. Grant the developer group `edit` in `corral-team-a` so corral can create the
   ServiceAccount, Secret, and token.

For example:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: corral-team-a
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: corral-team-a-view
  namespace: app-namespace
subjects:
  - kind: Group
    name: system:serviceaccounts:corral-team-a
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: corral-team-a-developers
  namespace: corral-team-a
subjects:
  - kind: Group
    name: team-a-developers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
```

The developer's runtime permissions are:

| Operation | Verbs | Resource |
| --- | --- | --- |
| Create and remove the session ServiceAccount | `create`, `delete`, `list` | `serviceaccounts` |
| Create and remove the revocation Secret | `create`, `delete`, `list` | `secrets` |
| Request the token | `create` | `serviceaccounts/token` |
| Check whether the namespace exists | `get` | `namespaces` |

The last permission is optional. If namespace reads are forbidden, corral continues
with a warning and reports a less specific error if the namespace does not exist.

> [!warning]
> Anyone with `edit` in the dedicated corral namespace can create a ServiceAccount
> and request a token that inherits the administrator's group bindings. Grant `edit`
> only to users trusted with all access assigned to that ServiceAccount group.

The [threat model](../explanation/threat-model.md#what-corral-does-not-protect-against)
explains why those users share the access assigned to this namespace.

### Enable preProvisioned mode

Name the namespace prepared by the administrator:

```yaml
providers:
  kubernetes:
    enabled: true
    mode: preProvisioned
    serviceAccountNamespace: corral-team-a
```

`serviceAccountNamespace` is required and has no default in this mode.
`permissions` must be absent because corral does not create RBAC bindings.

The kubeconfig context defaults to `serviceAccountNamespace`, `corral-team-a` in this
example. Specify the target namespace when working with application resources:

```sh
kubectl -n app-namespace get pods
```

## Verify the session

Launch a new session, then run:

```sh
kubectl auth whoami
kubectl auth can-i --list --namespace app-namespace
kubectl auth can-i get pods --namespace app-namespace
```

The first command should name the per-session ServiceAccount. Replace
`app-namespace` with a namespace the session should access. The other commands then
reflect the managed-mode `permissions` or the pre-provisioned group bindings in that
namespace. An unqualified `kubectl auth can-i --list` checks only the kubeconfig
context's current namespace.

The requested `tokenLifetime` defaults to `8h` and cannot exceed `24h`. A cluster may
return a shorter expiry. The startup banner reports the actual expiry.

A direct agent `Read` of the temporary kubeconfig is intentionally blocked because it
contains the bearer token. Kubernetes clients can use `$KUBECONFIG` without placing the
token in model context. See
[the kubeconfig `Read` block](troubleshooting.md#the-kubeconfig-read-block).

## Fix common failures

- **`forbidden: cannot create resource "serviceaccounts"`:** In managed mode,
  grant the host identity the required ServiceAccount permissions. In
  `preProvisioned` mode, grant it `edit` in the dedicated corral namespace.
- **The host identity cannot grant a role:** Give it the permissions being assigned
  or `bind` permission on the referenced Role or ClusterRole, or use
  `preProvisioned` mode.
- **The namespace was not provisioned:** Create the configured
  `serviceAccountNamespace` and its bindings before using `preProvisioned` mode.
- **The token expires earlier than requested:** The cluster capped the lifetime. Use
  the actual expiry reported in the startup banner.
