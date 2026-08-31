# KernelCI Dashboard host

This playbook configures the host reached by `ssh dashboard`.  It models the
host-level services observed on the current Debian 12 VM while preserving the
deployment boundary established by
[`kernelci/dashboard`](https://github.com/kernelci/dashboard).

## Ownership boundary

Ansible owns:

- Docker CE and the Compose plugin;
- Docker JSON-file log rotation;
- the `azureuser` Docker-group membership used by GitHub Actions;
- nginx routing for production (`127.0.0.1:8011`) and staging
  (`127.0.0.1:9000`);
- the shared Let's Encrypt certificate and its twice-daily renewal timer;
- UFW rules, without deleting unrelated existing rules;
- node exporter on port 2000;
- Uptime Kuma on `127.0.0.1:3001`; and
- Dozzle on `127.0.0.1:8080` through a read-only Docker API proxy; and
- permissions on existing workflow environment files.

GitHub Actions continues to own the application deployments:

- `deploy-containers.yaml` publishes the backend, frontend, and proxy images to
  GHCR after pushes to `main`;
- a push to `main` runs CI and then `deploy-staging.yaml`, replacing
  `~/dashboard-staging`, copying `~/.env-staging`, building the images locally,
  and running `docker compose up`;
- `deploy-production.yaml` is manually dispatched, replaces
  `~/dashboard-production`, copies `~/.env-production`, pulls the pre-built GHCR
  images, and runs `docker compose -f docker-compose-next.yml up`; and
- both workflows prune old Docker build and image data after deployment.

The repository also contains `staging-db.yaml`, which deploys the self-hosted
Dashboard under `/srv/kcidb-ng` on the separate KCIDB staging database host. It
does not target `ssh dashboard`. The team-sync workflow only updates GitHub
organization/team membership and likewise does not configure this VM.

The role therefore never checks out `kernelci/dashboard`, edits either
application directory, or stores the two secret environment files.

One workflow caveat remains outside this playbook: the production workflow's
`tag` input is currently used in notifications, but the remote commands check
out the workflow's `GITHUB_SHA` and pull images tagged `latest`. Selecting a tag
therefore does not currently pin either the checkout or the deployed images.

## Run it

The inventory intentionally uses the existing SSH alias:

```console
cd playbooks/dashboard
ansible-playbook main.yml --check --diff
ansible-playbook main.yml
```

If `ssh dashboard` is not configured locally, set `ansible_host` in
`inventory.yaml` or pass a temporary inventory override.

For a replacement host, first point all three DNS names at it and make TCP port
80 reachable.  Then request the initial certificate explicitly:

```console
ansible-playbook main.yml -e dashboard_request_certificate=true
```

Certificate issuance is disabled by default.  An existing certificate is
detected and used automatically, so routine runs on the current host do not
contact Let's Encrypt.

Before either application workflow runs, provision these files out-of-band as
`azureuser` with mode `0600`:

```text
/home/azureuser/.env-staging
/home/azureuser/.env-production
```

The playbook reports missing files but does not create empty substitutes.

## Local container monitoring

Dozzle is deliberately not exposed through nginx or a public firewall rule. It
connects to Docker through an internal socket-proxy network where write methods
and unrelated API sections are disabled. Both containers use pinned image
digests, health checks, resource limits, and `restart: always`.

An enabled `dashboard-monitoring.service` also runs `docker compose up --wait`
after Docker starts, so the monitoring project is recreated and health-checked
at boot even if its containers were removed previously.

Forward both localhost services over the existing SSH access:

```console
ssh -N \
  -L 8080:127.0.0.1:8080 \
  -L 3001:127.0.0.1:3001 \
  dashboard
```

Then open Dozzle at <http://127.0.0.1:8080> and Uptime Kuma at
<http://127.0.0.1:3001>.

To deploy only Dozzle without reconciling the rest of the host role:

```console
ansible-playbook main.yml --tags dozzle
```
