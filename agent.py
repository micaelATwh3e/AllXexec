import argparse
import fcntl
import hashlib
import hmac
import json
import os
import platform
import signal
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
AGENT_LOCK_PATH = BASE_DIR / "agent.lock"
AGENT_STATE_DIR = BASE_DIR / "agent-state"
AGENT_STATE_DIR.mkdir(exist_ok=True)
load_dotenv(BASE_DIR / ".env")


class ManagedProcess:
    def __init__(self):
        self.process = None
        self.exit_code = None
        self.external_pid = None


class Agent:
    def __init__(
        self,
        server_url,
        token,
        poll_interval=5,
        sync_interval=15,
        heartbeat_interval=15,
        allow_insecure_http=False,
        ca_cert=None,
    ):
        self.server_url = server_url.strip().rstrip("/")
        self.token = token.strip()
        self.poll_interval = max(1, int(poll_interval))
        self.sync_interval = max(self.poll_interval, int(sync_interval))
        self.heartbeat_interval = max(self.poll_interval, int(heartbeat_interval))
        self.processes = {}
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self._lock_file_handle = None
        if ca_cert:
            self.session.verify = ca_cert

        parsed = urlparse(self.server_url)
        if parsed.scheme != "https" and not allow_insecure_http:
            raise ValueError("Server URL must use https:// unless --allow-insecure-http is set.")

        self._acquire_instance_lock()

    def _acquire_instance_lock(self):
        handle = open(AGENT_LOCK_PATH, "a+")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            raise RuntimeError("Another agent instance is already running on this machine.")

        handle.seek(0)
        handle.truncate(0)
        handle.write(str(os.getpid()))
        handle.flush()
        self._lock_file_handle = handle

    def close(self):
        if not self._lock_file_handle:
            return
        try:
            fcntl.flock(self._lock_file_handle.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            self._lock_file_handle.close()
        except Exception:
            pass
        self._lock_file_handle = None

    def _signed_headers(self, method, path, body):
        timestamp = str(int(time.time()))
        payload = method.upper().encode() + b"\n" + path.encode() + b"\n" + timestamp.encode() + b"\n" + body
        signature = hmac.new(self.token.encode(), payload, hashlib.sha256).hexdigest()
        return {
            "Authorization": f"Bearer {self.token}",
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Signature": signature,
        }

    def _pid_file(self, app_id):
        return AGENT_STATE_DIR / f"app-{app_id}.pid"

    def _is_pid_alive(self, pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except Exception:
            return False
        return True

    def _read_saved_pid(self, app_id):
        path = self._pid_file(app_id)
        if not path.exists():
            return None
        try:
            value = int(path.read_text().strip())
        except Exception:
            return None
        return value

    def _write_saved_pid(self, app_id, pid):
        self._pid_file(app_id).write_text(str(pid))

    def _clear_saved_pid(self, app_id):
        path = self._pid_file(app_id)
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass

    def _request_json(self, method, path, payload=None):
        body = b""
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        headers = self._signed_headers(method, path, body)
        response = self.session.request(
            method=method.upper(),
            url=f"{self.server_url}{path}",
            data=body if body else None,
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        if response.content:
            return response.json()
        return {}

    def register(self):
        payload = {
            "hostname": platform.node(),
            "os": platform.platform(),
        }
        self._request_json("POST", "/api/agent/register", payload)

    def fetch_apps(self):
        result = self._request_json("GET", "/api/agent/apps")
        return result.get("apps", [])

    def heartbeat(self):
        statuses = []
        for app_id, managed in self.processes.items():
            process_alive = managed.process and managed.process.poll() is None
            external_alive = managed.external_pid and self._is_pid_alive(managed.external_pid)

            if process_alive:
                state = "running"
                pid = managed.process.pid
            elif external_alive:
                state = "running"
                pid = managed.external_pid
            else:
                if managed.process and managed.process.poll() is not None:
                    managed.exit_code = managed.process.returncode
                if managed.external_pid and not external_alive:
                    managed.external_pid = None
                    self._clear_saved_pid(app_id)
                state = "stopped"
                pid = None

            statuses.append(
                {
                    "app_id": app_id,
                    "state": state,
                    "pid": pid,
                    "last_exit": managed.exit_code,
                }
            )

        payload = {"statuses": statuses}
        self._request_json("POST", "/api/agent/heartbeat", payload)

    def ensure_running(self, app_item):
        app_id = app_item["id"]
        cwd = (app_item.get("cwd") or "").strip()
        command = (app_item.get("command") or "").strip()

        managed = self.processes.get(app_id)
        if managed is None:
            managed = ManagedProcess()
            self.processes[app_id] = managed

        if managed.process and managed.process.poll() is None:
            return

        if managed.external_pid and self._is_pid_alive(managed.external_pid):
            return

        if managed.process and managed.process.poll() is not None:
            managed.exit_code = managed.process.returncode

        if managed.external_pid and not self._is_pid_alive(managed.external_pid):
            managed.external_pid = None
            self._clear_saved_pid(app_id)

        if managed.process is None and managed.external_pid is None:
            saved_pid = self._read_saved_pid(app_id)
            if saved_pid and self._is_pid_alive(saved_pid):
                managed.external_pid = saved_pid
                return

        if cwd and not Path(cwd).exists():
            return

        if not command:
            return

        log_path = Path.cwd() / f"agent-app-{app_id}.log"
        log_handle = open(log_path, "ab")

        try:
            managed.process = subprocess.Popen(
                command,
                shell=True,
                cwd=cwd if cwd else None,
                stdout=log_handle,
                stderr=log_handle,
                executable="/bin/bash",
                preexec_fn=os.setsid,
            )
            managed.external_pid = managed.process.pid
            self._write_saved_pid(app_id, managed.process.pid)
        except Exception:
            pass

    def stop_removed(self, desired_ids):
        for app_id in list(self.processes.keys()):
            if app_id not in desired_ids:
                self.stop_app(app_id)
                del self.processes[app_id]

    def stop_app(self, app_id):
        managed = self.processes.get(app_id)
        if not managed:
            return

        target_pid = None
        if managed.process and managed.process.poll() is None:
            target_pid = managed.process.pid
        elif managed.external_pid and self._is_pid_alive(managed.external_pid):
            target_pid = managed.external_pid

        if target_pid:
            try:
                os.killpg(os.getpgid(target_pid), signal.SIGTERM)
            except Exception:
                pass
        self._clear_saved_pid(app_id)
        managed.external_pid = None

    def run(self):
        last_register = 0.0
        last_sync = 0.0
        last_heartbeat = 0.0
        desired = {}
        while True:
            try:
                now = time.monotonic()

                if now - last_register >= 60:
                    self.register()
                    last_register = now

                if now - last_sync >= self.sync_interval:
                    apps = self.fetch_apps()
                    desired = {item["id"]: item for item in apps if item.get("always_on", True) and item.get("enabled", True)}
                    desired_ids = set(desired.keys())

                    self.stop_removed(desired_ids)
                    last_sync = now

                for app_item in desired.values():
                    self.ensure_running(app_item)

                if now - last_heartbeat >= self.heartbeat_interval:
                    self.heartbeat()
                    last_heartbeat = now
            except requests.HTTPError as exc:
                details = ""
                if exc.response is not None:
                    details = f" body={exc.response.text[:300]}"
                print(f"HTTP error: {exc}{details}")
            except requests.RequestException as exc:
                print(f"Connection error: {exc}")
            except Exception as exc:
                print(f"Unexpected error: {exc}")

            time.sleep(self.poll_interval)


def parse_args():
    parser = argparse.ArgumentParser(description="App admin client agent")
    parser.add_argument(
        "--server",
        default=os.environ.get("AGENT_SERVER"),
        help="Server URL, e.g. https://10.0.0.2:8080 (or AGENT_SERVER in .env)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("AGENT_TOKEN"),
        help="Client token created in admin UI (or AGENT_TOKEN in .env)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=int(os.environ.get("AGENT_INTERVAL", "5")),
        help="Local supervision loop interval seconds (or AGENT_INTERVAL in .env)",
    )
    parser.add_argument(
        "--sync-interval",
        type=int,
        default=int(os.environ.get("AGENT_SYNC_INTERVAL", "15")),
        help="How often to fetch desired apps from server in seconds (or AGENT_SYNC_INTERVAL in .env)",
    )
    parser.add_argument(
        "--heartbeat-interval",
        type=int,
        default=int(os.environ.get("AGENT_HEARTBEAT_INTERVAL", "15")),
        help="How often to send heartbeat status in seconds (or AGENT_HEARTBEAT_INTERVAL in .env)",
    )
    parser.add_argument(
        "--ca-cert",
        default=os.environ.get("AGENT_CA_CERT"),
        help="Path to CA certificate file for HTTPS verification (or AGENT_CA_CERT in .env)",
    )
    parser.add_argument("--allow-insecure-http", action="store_true", help="Allow plain HTTP (not secure)")
    args = parser.parse_args()
    if args.server:
        args.server = args.server.strip()
    if args.token:
        args.token = args.token.strip()
    if args.ca_cert:
        args.ca_cert = args.ca_cert.strip()
    if not args.server:
        parser.error("Missing server URL. Provide --server or set AGENT_SERVER in .env")
    if not args.token:
        parser.error("Missing token. Provide --token or set AGENT_TOKEN in .env")
    if args.interval < 1:
        parser.error("--interval must be >= 1")
    if args.sync_interval < args.interval:
        args.sync_interval = args.interval
    if args.heartbeat_interval < args.interval:
        args.heartbeat_interval = args.interval
    if not args.allow_insecure_http and os.environ.get("AGENT_ALLOW_INSECURE_HTTP", "0") == "1":
        args.allow_insecure_http = True
    return args


def main():
    args = parse_args()
    agent = Agent(
        server_url=args.server,
        token=args.token,
        poll_interval=args.interval,
        sync_interval=args.sync_interval,
        heartbeat_interval=args.heartbeat_interval,
        allow_insecure_http=args.allow_insecure_http,
        ca_cert=args.ca_cert,
    )
    try:
        agent.run()
    finally:
        agent.close()


if __name__ == "__main__":
    main()
