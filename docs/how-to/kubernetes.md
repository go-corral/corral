# Set up Kubernetes credentials

The Kubernetes provider creates a per-session ServiceAccount and token and writes it to a kubeconfig mounted read-only in the sandbox. When the session ends, corral removes the ServiceAccount and related resources. `corral gc` can remove resources left by a crashed session.

You can choose who manages the ServiceAccount's RBAC:

- [`managed`](#managed-mode) lets corral create bindings from config. You need the cluster permissions required to create those bindings.
- [`preProvisioned`](#preprovisioned-mode) uses bindings created by an administrator. You only need `edit` in a dedicated corral namespace.

Both modes require a working host kubeconfig and context.

## Managed mode

Managed mode is the default. This minimal config creates the session ServiceAccount in a namespace named `corral` and assigns cluster-wide `view` permissions:

```yaml
providers:
  kubernetes:
    enabled: true
```

Custom permissions are configurable. This example grants `edit` only in namespaces labeled for the platform team:

```yaml
providers:
  kubernetes:
    enabled: true
    permissions:
      - clusterRole: edit
        namespaceSelector:
          matchLabels:
            team: platform
```

A permission must select a scope (`clusterWide: true` or `namespaceSelector`) and a role (`clusterRole` or `role`). Corral will warn when "insecure" roles are assigned (configurable via `readOnlyRoles`). See [`providers.kubernetes`](../reference/config.md#providerskubernetes) for possible fields and selector operators.

### Host RBAC for managed mode

You'll need these permissions:

| Operation                                     | Verbs                             | Resource                |
| --------------------------------------------- | --------------------------------- | ----------------------- |
| Create and remove the session ServiceAccount  | `create`, `delete`, `list`        | `serviceaccounts`       |
| Request the token                             | `create`                          | `serviceaccounts/token` |
| Check the ServiceAccount namespace            | `get`                             | `namespaces`            |
| Create the ServiceAccount namespace if absent | `create`                          | `namespaces`            |
| Resolve a `namespaceSelector`                 | `list`                            | `namespaces`            |
| Manage cluster-wide grants                    | `create`, `get`, `delete`, `list` | `clusterrolebindings`   |
| Manage namespaced grants                      | `create`, `get`, `delete`, `list` | `rolebindings`          |

Kubernetes also prevents privilege escalation through role bindings. You can't assign a role with more privileges than you already have. If you need privilege escalation (`kubectl --as`) to create these resources, set `providers.kubernetes.as`.

## PreProvisioned mode

If you'd like to use corral but don't have the necessary permissions to use the manage mode, it's also possible to create the namespace and role bindings in advance. The steps are described below. `preProvisioned` mode does not allow to specify permissions at launch because they must be assigned by the cluster administrator.

In this mode, the administrator creates a namespace and assigns a role to all ServiceAccounts in this namespace. You only need edit permissions in the namespace to create a ServiceAccount and a token to be used for the corral session.

### Enable preProvisioned mode

Enable `preProvisioned` mode and set the namespace assigned by the administrator:

```yaml
providers:
  kubernetes:
    enabled: true
    mode: preProvisioned
    serviceAccountNamespace: corral-team-a
```

`serviceAccountNamespace` is required and has no default in this mode.

The kubeconfig context defaults to `serviceAccountNamespace`, `corral-team-a` in this example. Specify the target namespace when working with application resources.

### Cluster preparation

An administrator must:

1. Create a dedicated namespace, such as `corral-team-a`, ideally with no other workloads.
2. In the target namespaces or cluster-wide, bind the group `system:serviceaccounts:corral-team-a` to the roles it should receive.
3. Grant the developers `edit` in `corral-team-a` so corral can create the ServiceAccount, Secret, and token.

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

The developer's minimal necessary permissions are:

| Operation                                    | Verbs                      | Resource                |
| -------------------------------------------- | -------------------------- | ----------------------- |
| Create and remove the session ServiceAccount | `create`, `delete`, `list` | `serviceaccounts`       |
| Create and remove the revocation Secret      | `create`, `delete`, `list` | `secrets`               |
| Request the token                            | `create`                   | `serviceaccounts/token` |
| Check whether the namespace exists           | `get`                      | `namespaces`            |

The last permission is optional. If namespace reads are forbidden, corral continues with a warning and reports a less specific error if the namespace does not exist.

## Use multiple clusters

It's possible to create credentials for multiple clusters at once, too. To do that, configure clusters in `providers.kubernetes.clusters`. Every configured cluster will become a context in a single kubeconfig in the sandbox.

```yaml
providers:
  kubernetes:
    enabled: true
    clusters:
      prod:
        default: true
        kubeconfig:
          path: ~/.kube/prod
      staging:
        kubeconfig:
          context: staging-admin
```

Each configured cluster needs information on which cluster it's associated to:

- `kubeconfig.path` points to the kubeconfig to use. A relative path resolves against the directory where you run `corral`. When no path is set, corral loads `$KUBECONFIG`, then `~/.kube/config`.
- `kubeconfig.context` sets the context to use. Without a context, corral uses the current context of your kubeconfig.

You cannot configure two different contexts against the same Kubernetes API address, they must be unique.

### Config inheritance

The top-level fields are inherited to the clusters. When `permissions` are defined for a cluster, they replace higher level `permissions` and do not extend them.

```yaml
providers:
  kubernetes:
    enabled: true
    permissions:
      - clusterRole: edit
        namespaceSelector:
          matchLabels:
            team: platform
    clusters:
      staging: {} # inherits the edit permission
      prod:
        permissions: # replaces it
          - clusterWide: true
            clusterRole: view
```

### Default context

Set `default: true` on one cluster. The session kubeconfig then sets `current-context` to that cluster, and `kubectl` uses it without `--context`. Other clusters need `kubectl --context <key>`.

### Clean up with `corral gc`

`corral gc` checks every configured cluster, enabled or not. When it cannot load or reach a cluster, it reports an error, checks the other clusters, and exits with a non-zero status.

## Verify the session

Launch a new session, then run:

```sh
kubectl auth whoami
kubectl auth can-i --list --namespace app-namespace
kubectl auth can-i get pods --namespace app-namespace
```

The first command should show the per-session ServiceAccount. Replace `app-namespace` with a namespace the session should access. The other commands then reflect the managed-mode `permissions` or the pre-provisioned group bindings in that namespace.

With multiple clusters, add `--context <key>` to reach a cluster that is not the default:

```sh
kubectl --context staging auth whoami
```

The requested `tokenLifetime` defaults to `8h` and cannot exceed `24h`. A cluster may return a shorter expiry. The startup banner reports the actual expiry.

## Fix common failures

- **`forbidden: cannot create resource "serviceaccounts"`:** In `preProvisioned` mode, you need `edit` in the dedicated corral namespace.
- **The host identity cannot grant a role:** You need to already posess the permissions being assigned or a `bind` permission on the referenced Role or ClusterRole, or use `preProvisioned` mode.
- **The namespace was not provisioned:** Create the configured `serviceAccountNamespace` and its bindings before using `preProvisioned` mode.
- **The token expires earlier than requested:** The cluster capped the lifetime.
- **`KUBECONFIG names several files and ... is in a sandbox-writable location`:** corral loads an approved kubeconfig only as a single file. Set `KUBECONFIG` to that one file. For a declared cluster, set its `kubeconfig.path` to that file.
