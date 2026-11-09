# iLO 4 Console

A modern, lightweight web console for HPE iLO 4 — the management processor in ProLiant Gen8 and Gen9 servers. It replaces the dated iLO web interface with a fast fleet dashboard and a clean per-server view, and talks to each iLO over its Redfish API. Everything runs in a single small Docker container.

![Version](https://img.shields.io/badge/version-v0.02-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Fleet dashboard** — every server at a glance: power state, health, live power draw, total fleet watts, and which machines are running now
- **Per-server view** — Overview, System (model, CPUs, memory, BIOS, firmware), Power, Logs, and Settings tabs
- **Power control** — On, Force Off, Force Restart, NMI, and Push Power Button. The console reads each iLO's own supported action list and only offers what that firmware actually accepts (on iLO 4, Push Power Button is the graceful ACPI shutdown)
- **Thermal** — all temperature sensors and fans, live from the chassis
- **Logs** — the iLO Event Log, newest first
- **Fast by design** — a background refresher keeps data warm so pages load instantly, and the Redfish client holds one persistent session per iLO instead of paying a fresh TLS handshake on every call
- **Saved logins** — add each server once by IP with its iLO credentials; one click switches between servers, and a button opens the original iLO interface when you need it
- **Console login** — a single password (set on first visit) protects the console; iLO passwords are stored encrypted at rest, and logins and power actions are written to an audit log

## Requirements

- Docker with the Compose plugin
- iLO 4 with firmware **2.30 or newer** (Redfish). Gen8 and Gen9 servers qualify; iLO 3 (Gen7) has no Redfish interface and is not supported
- Network reachability from the Docker host to each iLO on HTTPS (443)

## Quick start

```bash
git clone https://github.com/kaushikray2/ilo4-console.git
cd ilo4-console
cp .env.example .env        # optional: change the host port (default 8080)
docker compose up -d --build
```

Then open `http://<docker-host>:8080`:

1. On the first visit you will be asked to create the console password.
2. Click **+ Add server**, enter the iLO's IP address and its iLO username and password, and save.
3. Repeat for each server. Everything is stored in the `./data` folder next to the compose file — back that folder up to keep your registry.

## Configuration

| Setting | Where | Default |
| --- | --- | --- |
| Host port | `.env` → `ILO_PORT` | `8080` |
| Server registry, console password, audit log | `./data/` | created on first run |

## Security notes

- **Run it on a trusted LAN only.** The console login travels over plain HTTP by design, for home-lab and management-network use. Do not port-forward it to the internet; if you need remote access, put it behind a VPN or a TLS-terminating reverse proxy.
- iLO passwords are encrypted at rest in `data/servers.json`; the encryption key is a separate file (`data/.key`, mode 600). Protect the `data/` folder as you would a password file.
- The console holds **one** Redfish session per iLO and deletes it when it shuts down, so it stays well within the iLO's small session limit.
- iLO self-signed certificates are accepted (management networks are typically not PKI-managed); all traffic still runs over TLS to each iLO.

## How it works

One container, two parts:

- A Python (standard library only) service that serves the UI, keeps the server registry, polls each iLO in the background (status ~25 s, thermal ~45 s, logs ~2 min), and proxies power actions live.
- A React front end built at image-build time — the runtime image is just `python:3.12-alpine` (~75 MB), with no runtime dependencies to install or update.

## License

MIT — see [LICENSE](LICENSE).

---

Developed by [SiliconBrane Inc.](https://siliconbrane.com)

Version **v0.02**
