# mihomo-warp-proxy

[![CI](https://github.com/underhax/mihomo-warp-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/underhax/mihomo-warp-proxy/actions/workflows/ci.yml)
[![GitHub last commit](https://img.shields.io/github/last-commit/underhax/mihomo-warp-proxy)](https://github.com/underhax/mihomo-warp-proxy/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/underhax/mihomo-warp-proxy)](https://github.com/underhax/mihomo-warp-proxy/issues)
[![GitHub repo size](https://img.shields.io/github/repo-size/underhax/mihomo-warp-proxy)](https://github.com/underhax/mihomo-warp-proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Scratch-based container integrating [**mihomo**](https://github.com/MetaCubeX/mihomo) (Clash Meta proxy core) and [**wgcf**](https://github.com/ViRb3/wgcf) (Cloudflare WARP account and profile generator) to expose an authenticated mixed SOCKS5/HTTP(S) proxy.

## System Design

This stack provides an authenticated proxy gateway built on the principle of least privilege and attack surface reduction:

* The scratch container contains only the custom Go supervisor, static `mihomo` and `wgcf` binaries, and CA root certificates, excluding shells, package managers, and system utilities.
* The Go supervisor manages container bootstrap, validates configuration boundaries, securely synchronizes geodata routing databases, and provisions WireGuard credentials via `wgcf`.
* Outbound connectivity is routed through a Cloudflare WARP WireGuard tunnel, with support for device `reserved` bytes extraction, configurable endpoint ports, and AmneziaWG packet obfuscation.
* In-place configuration synchronization applies managed runtime settings while preserving all user-defined custom configurations, proxies, and routing rules across container restarts.
* All processes execute under a dedicated unprivileged user and group configured via environment variables.
* The runtime environment enforces a read-only root filesystem, dropped Linux capabilities, hardened tmpfs mounts, and credential isolation through Docker Secrets.
* Health checks execute directly via in-process socket probes without external utilities or shell dependencies.

---

<details>
<summary><strong>Directory Structure</strong></summary>

Production directory layout on the host (`/home/mihomo`):

```text
├── docker-compose.yaml                # Production deployment manifest
├── .env                               # Container environment configuration
├── data/                              # Persistent storage for mihomo configuration and geodata
├── wgcf/                              # Persistent storage for Cloudflare WARP credentials and profile
└── secrets/                           # Docker secrets directory
    ├── mwp_proxy_user                 # Proxy authentication username
    ├── mwp_proxy_pass                 # Proxy authentication password
    ├── mwp_geo_auth_user              # Upstream HTTP basic auth username (optional)
    ├── mwp_geo_auth_pass              # Upstream HTTP basic auth password (optional)
    └── mwp_warp_plus_key              # Cloudflare WARP+ license key (optional)
```

</details>

---

<details>
<summary><strong>Deployment &amp; Setup</strong></summary>

### Prerequisites

* **Docker Engine & Compose:** Ensure Docker Engine and the Docker Compose plugin are installed on the host. Follow the official installation guide for [Ubuntu](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository).
* **External Gateway Network (Optional):** Required only when connecting services via an [Angie Reverse Proxy](https://github.com/webstudiobond/angie-docker-compose), which automatically provisions the shared `frontend_gateway` network. If deploying standalone without the Angie stack, create it manually:

  ```bash
  docker network create frontend_gateway
  ```

* **Outbound UDP Traffic:** Standard Linux distributions permit outbound traffic by default. If deploying behind a restrictive egress firewall, ensure outbound UDP is allowed to your selected WARP endpoint port (supported: `2408`, `500`, `1701`, or `4500`) for WireGuard handshakes.

### 1. Create a Dedicated System User

Choose a dedicated, unprivileged numeric ID unique to this service on your host and verify that it is not already in use by another user or group:

```bash
APP_UID=<CHOSEN_UID>

getent passwd ${APP_UID}
getent group ${APP_UID}
```

```bash
sudo useradd -M -d /home/mihomo -s /usr/sbin/nologin -u ${APP_UID} -U mihomo
```

```bash
sudo mkdir -p /home/mihomo
sudo chown root:mihomo /home/mihomo
sudo chmod 0750 /home/mihomo
```

### 2. Prepare Directory Structure & Permissions

```bash
sudo mkdir -p /home/mihomo/{secrets,data,wgcf}

sudo chown root:mihomo /home/mihomo/secrets
sudo chmod 0750 /home/mihomo/secrets

sudo chown -R mihomo:mihomo /home/mihomo/{data,wgcf}
sudo chmod 0700 /home/mihomo/{data,wgcf}
```

### 3. Fetch Deployment Manifests

```bash
REPO="https://raw.githubusercontent.com/underhax/mihomo-warp-proxy/main"

sudo curl -fsSL ${REPO}/docker-compose.yaml -o /home/mihomo/docker-compose.yaml
sudo curl -fsSL ${REPO}/.env.example -o /home/mihomo/.env

sudo chown root:root /home/mihomo/{docker-compose.yaml,.env}
sudo chmod 0600 /home/mihomo/{docker-compose.yaml,.env}
```

```bash
sudo sed -i "s/^APP_UID=.*/APP_UID=${APP_UID}/" /home/mihomo/.env
sudo sed -i "s/^APP_GID=.*/APP_GID=${APP_UID}/" /home/mihomo/.env
```

### 4. Configure Environment & CPU Variant

Detect the supported instruction set extensions on an amd64 host:

```bash
awk '/flags/{if (/avx2/) {print "v3"; exit} if (/sse4_2/) {print "v2"; exit} print "v1"; exit}' /proc/cpuinfo
```

Review environment options and set `MIHOMO_CPU_VARIANT` (e.g. `v3`, `v2`, or leave empty for `v1`; on ARM64 hosts leave it empty):

```bash
sudo nano /home/mihomo/.env
```

### 5. Provision Authentication Secrets

Generate high-entropy credentials without trailing newlines directly into Docker secret files:

```bash
sudo touch /home/mihomo/secrets/mwp_proxy_{user,pass}
sudo chown root:mihomo /home/mihomo/secrets/*
sudo chmod 0440 /home/mihomo/secrets/*

pwgen -s 64 1 | tr -d '\n' | sudo tee /home/mihomo/secrets/mwp_proxy_user > /dev/null
pwgen -s 128 1 | tr -d '\n' | sudo tee /home/mihomo/secrets/mwp_proxy_pass > /dev/null
```

### 6. Start the Service

```bash
docker compose -f /home/mihomo/docker-compose.yaml pull
docker compose -f /home/mihomo/docker-compose.yaml up -d
```

</details>

---

<details>
<summary><strong>Permissions &amp; Ownership</strong></summary>

### Host Permissions & Privilege Separation

The stack enforces strict host-level privilege separation across three ownership tiers so that even in the event of a container compromise, the process cannot modify deployment manifests or secret files:

* `root:root` (`0600`): `docker-compose.yaml` and `.env` (accessible exclusively to host root).
* `root:mihomo` (`0750`/`0440`): `/home/mihomo` base directory (`0750`), `secrets/` directory (`0750`), and secret files (`mwp_proxy_user`, `mwp_proxy_pass`, etc. at `0440`; read-only to container, immutable to runtime processes).
* `mihomo:mihomo` (`0700`/`0600`): `data/` and `wgcf/` persistent storage. Managed with strict DAC: directories `0700`, files `0600`.

| Host path | Owner | Mode | Reason |
| --- | --- | --- | --- |
| `/home/mihomo` | `root:mihomo` | `0750` | Allow service traversal without access for other users |
| `docker-compose.yaml`, `.env` | `root:root` | `0600` | Host-only manifests and environment settings |
| `secrets/` directory | `root:mihomo` | `0750` | Traverse-only access for the service group |
| `secrets/*` | `root:mihomo` | `0440` | Read-only to the service group |
| `data/`, `wgcf/` directories | `mihomo:mihomo` | `0700` | Private writable runtime storage |
| `data/`, `wgcf/` files | `mihomo:mihomo` | `0600` | Private runtime databases, configuration, and WireGuard profile |

### One-Shot Permission Reset (Running Stack)

Use this self-contained block to apply or restore canonical ownership and permissions on an existing or migrated installation without stopping the stack:

```bash
sudo chown root:mihomo /home/mihomo
sudo chmod 0750 /home/mihomo

sudo chown root:root /home/mihomo/{docker-compose.yaml,.env}
sudo chmod 0600 /home/mihomo/{docker-compose.yaml,.env}

sudo chown -R root:mihomo /home/mihomo/secrets
sudo chmod 0750 /home/mihomo/secrets
sudo find /home/mihomo/secrets -type f -exec chmod 0440 {} +

sudo chown -R mihomo:mihomo /home/mihomo/{data,wgcf}
sudo find /home/mihomo/{data,wgcf} -type d -exec chmod 0700 {} +
sudo find /home/mihomo/{data,wgcf} -type f -exec chmod 0600 {} +
```

</details>

---

<details>
<summary><strong>Operation &amp; Maintenance</strong></summary>

### Verifying Service Health

Check container status and resource consumption:

```bash
sudo docker compose -f /home/mihomo/docker-compose.yaml ps
sudo docker stats --no-stream mihomo
```

### Inspecting Runtime Logs

Follow service logs in real time:

```bash
sudo docker compose -f /home/mihomo/docker-compose.yaml logs -f
```

### Tearing Down the Stack

Stop and remove the container:

```bash
sudo docker compose -f /home/mihomo/docker-compose.yaml down
```

</details>

---

<details>
<summary><strong>Gateway Integration</strong></summary>

Containers attached to the `frontend_gateway` network can access the proxy directly without exposing ports to the host (replace `7890` with your configured `PROXY_PORT`):

* `http://mihomo:7890` (HTTP)
* `socks5://mihomo:7890` (SOCKS5)

If authentication is enabled, pass credentials in the URI (`http://<user>:<password>@mihomo:7890` or `socks5://<user>:<password>@mihomo:7890`). For example, in [**invidious-docker**](https://github.com/underhax/invidious-docker) you can configure the proxy via its Docker secrets (`proxy_host`, `proxy_port`, `proxy_user`, `proxy_pass`).

For exposing custom inbound proxy protocols (such as VLESS over WebSocket, gRPC, or XHTTP) via an external [**Edge Angie**](https://github.com/webstudiobond/angie-docker-compose) reverse proxy, refer to the example configuration [`mihomo.conf`](https://github.com/webstudiobond/angie-docker-compose/blob/main/data/conf.d/domains/mihomo.conf).

This configuration is strictly a reference template and must not be copied as-is:

* Retain only the protocols configured in your Mihomo setup and discard unused blocks.
* Replace sample upstream ports (`10001`, `10002`, `10003`) with the actual inbound ports defined in `/home/mihomo/data/config.yaml`.
* Replace predictable example paths (`/ws`, `/grpc`, `/xhttp-one/`) with unique, unpredictable secret paths for defense-in-depth.

</details>

---

<details>
<summary><strong>Development</strong></summary>

For local compilation, testing, static analysis, and CI/CD details, see **[DEVELOPMENT.md](DEVELOPMENT.md)**.

</details>

---

<details>
<summary><strong>License &amp; Attribution</strong></summary>

## License & Attribution

This repository and deployment architecture are licensed under the [MIT License](LICENSE).

**mihomo (Clash Meta):** Open-source proxy kernel developed by [MetaCubeX](https://github.com/MetaCubeX/mihomo) under the [MIT License](https://github.com/MetaCubeX/mihomo/blob/main/LICENSE).

**wgcf:** Cross-platform Cloudflare WARP account manager and WireGuard profile generator developed by [ViRb3](https://github.com/ViRb3/wgcf) under the [MIT License](https://github.com/ViRb3/wgcf/blob/master/LICENSE).

</details>
