# Admin app runner

A minimal admin site to manage always-on apps on this server and on connected clients.

## Security

- Admin UI now requires login (password-based session auth).
- Agent API now requires signed requests using HMAC with per-client token.
- Use HTTPS between client and server.

## Features

- Web admin UI for:
  - creating clients (with token auth)
  - adding apps to server or client targets
  - enabling/disabling and deleting apps
  - viewing app status and client heartbeat
- Always-on supervision:
  - server runs apps assigned to `Server`
  - client agent runs apps assigned to that client
  - auto-restarts when app exits
- Supports command styles for `.py`, `.sh`, and binaries:
  - `python app.py`
  - `./run.sh`
  - `/path/to/binary --flag`
  - `/path/to/project/.venv/bin/python app.py`

## Install

```bash
cd /path/to/admin
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Run server

Set admin credentials in `.env` (preferred) or export env vars:

```bash
# edit .env and set:
# ADMIN_SECRET_KEY=...
# ADMIN_PASSWORD=...
```

```bash
source .venv/bin/activate
python server.py
```

Open: `http://localhost:8080`

For production, terminate TLS at a reverse proxy (nginx/caddy) and expose `https://...` to agents.

## Add server app example

In the UI, set:

- Target: `Server (this machine)`
- Working directory: `/path/to/project/`
- Command: `/path/to/project/.venv/bin/python app.py`

## Create and connect a client

1. In UI: create a client (get token).
2. On client machine:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests
cp .env.example .env
# set AGENT_SERVER and AGENT_TOKEN in .env
python agent.py
```

If you use a private/self-signed CA:

```bash
python agent.py --ca-cert /path/to/ca.crt
```

Development only (insecure HTTP):

```bash
python agent.py --allow-insecure-http
```

Then add apps in UI with target `Client: <name>`.

### Lower client CPU / network usage

The agent has separate loop intervals:

- `AGENT_INTERVAL` (default `5`): local process supervision loop
- `AGENT_SYNC_INTERVAL` (default `15`): fetch desired apps from server
- `AGENT_HEARTBEAT_INTERVAL` (default `15`): send status heartbeat

Example for low-power clients:

```bash
AGENT_INTERVAL=5
AGENT_SYNC_INTERVAL=30
AGENT_HEARTBEAT_INTERVAL=30
```

## Notes

- App output logs:
  - server apps: `logs/server-app-<id>.log`
  - client apps: `agent-app-<id>.log` (where agent runs)
- For production, run `server.py` and `agent.py` under systemd.
