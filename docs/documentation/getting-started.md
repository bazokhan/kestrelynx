# Setup instructions

KestreLynx runs as one container per Docker host or as a single-replica Deployment
inside a Kubernetes cluster. It discovers and scans the images used by running
containers, then sends the results to Slack or a webhook.

## Requirements

- A Docker host with Docker Compose or the Docker CLI, or a Kubernetes cluster
  with `kubectl` access and persistent storage
- At least one of the following notification destinations:
    - Slack Incoming Webhook
    - Slack bot token and channel
    - Webhook URL

## Run with Docker Compose

Download or clone the repository, then create a local configuration file.

```bash
cp config.example.yml config.yml
```

Configure at least one notification destination as shown below.

```yaml
notify:
  slack_webhook_url: "https://hooks.slack.com/services/..."
```

Start KestreLynx.

```bash
docker compose up -d
docker compose logs -f
```

The included Compose file persists scan history in the `kestrelynx-state`
volume. This state is required to preserve change-based notifications and
first-seen dates after the container is recreated.

## Run with Docker

```bash
docker run -d --name kestrelynx \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
  -v kestrelynx-state:/var/lib/kestrelynx \
  ghcr.io/kitsunetrail/kestrelynx:latest
```

!!! warning "Docker socket access"

    Enabling remediation pull requests lets KestreLynx create, start, and remove
    Docker work containers for language-package updates. The socket's `:ro`
    mount does not restrict Docker API operations and does not need to change
    to `:rw`.

On Docker, an optional Sensor (experimental) marks findings for packages in use and puts them
first within the same priority, without changing priority. Setup and observation
limits are described in [Runtime usage](runtime-usage.md).

### Remediation plans and pull requests

On Docker, you can also enable remediation plans and optional GitHub pull
requests. Both are disabled by default and do not require a Sensor.
See [Remediation plans and pull requests (experimental)](remediation.md) for
setup, notification meanings, and the checks to review before merging.

## Run on Kubernetes

Download or clone the repository. The `deploy/kubernetes/` directory contains
the following manifests.

| File | Resource |
| --- | --- |
| `serviceaccount.yaml` | ServiceAccount `kestrelynx` in the `kestrelynx` namespace. |
| `clusterrole.yaml` | ClusterRole granting read-only `get` and `list` access to Pods, Nodes, ReplicaSets, Deployments, StatefulSets, DaemonSets, Jobs, and CronJobs. |
| `clusterrolebinding.yaml` | ClusterRoleBinding assigning that role to the ServiceAccount. |
| `configmap.yaml` | ConfigMap `kestrelynx-config` containing `config.yml`. |
| `pvc.yaml` | PersistentVolumeClaim `kestrelynx-state`, requesting 1 GiB with `ReadWriteOnce` access. |
| `deployment.yaml` | Single-replica Deployment with the `Recreate` strategy, configuration mounted at `/etc/kestrelynx`, and state at `/var/lib/kestrelynx`. |

Configure at least one notification destination in
`deploy/kubernetes/configmap.yaml`. Its `config.yml` must set
`kubernetes.enabled: true` and must not set `docker.socket` to a value, including `""`.
Omitting the key or setting it to `null` is accepted, as is an empty `docker:` section.
When adapting `config.example.yml`, remove the entire `docker:` section.

One instance covers one cluster. By default, all namespaces are scanned;
`kubernetes.namespaces` restricts scanning to the listed namespaces.
Set `environment.name` to distinguish several instances posting to one Slack
channel. See [Configuration](configuration.md) for configuration options.

Trivy fetches images from the registry, so the scanner Pod needs registry
access. For private-registry images, create a Secret named
`kestrelynx-registry-auth` of type `kubernetes.io/dockerconfigjson` in the
`kestrelynx` namespace. Uncomment the `DOCKER_CONFIG` environment variable,
`registry-auth` volume mount, and Secret volume in
`deploy/kubernetes/deployment.yaml`. This mounts the Secret's
`.dockerconfigjson` key as `config.json` under `/etc/kestrelynx/docker`, the
directory specified by `DOCKER_CONFIG`. The `imagePullSecrets` of scanned
workloads are not reused.

Adjust the PVC's storage settings for the cluster, then create the namespace
and apply the prepared manifests.

```bash
kubectl create namespace kestrelynx
kubectl apply -f deploy/kubernetes/
kubectl logs -n kestrelynx deployment/kestrelynx -f
```

The PVC preserves scan history, first-seen dates, and the intel feed cache
after Pod recreation. Keep one replica and the `Recreate` strategy to avoid
overlapping Pods during updates. Two instances must not share one state
volume.

## Set the timezone

`schedule.daily_at` is interpreted in the timezone specified by `TZ`. The
Compose example uses UTC by default. Change it to the timezone of the host as
needed.

```yaml
environment:
  - TZ=Asia/Tokyo
```

The same setting applies to the `TZ` environment variable in
`deploy/kubernetes/deployment.yaml`, which also defaults to UTC.

## Reference pages

- See [Configuration](configuration.md) for configuration options.
- See [Notification logic](how-it-works.md) for notification logic.
