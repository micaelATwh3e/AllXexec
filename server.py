import atexit
import fcntl
import hashlib
import hmac
import os
import secrets
import signal
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template_string, request, session, url_for
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "admin.db"
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
SUPERVISOR_LOCK_PATH = BASE_DIR / "supervisor.lock"
load_dotenv(BASE_DIR / ".env")

app = Flask(__name__)
app.secret_key = os.environ.get("ADMIN_SECRET_KEY", "change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

_admin_password_hash = os.environ.get("ADMIN_PASSWORD_HASH")
if not _admin_password_hash and os.environ.get("ADMIN_PASSWORD"):
    _admin_password_hash = generate_password_hash(os.environ["ADMIN_PASSWORD"])


TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>App Admin</title>
  <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            background: #f4f6fb;
            color: #1f2937;
            line-height: 1.45;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 28px 20px 40px;
        }
        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 18px;
        }
        h1 {
            margin: 0;
            font-size: 1.7rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }
        .subtitle {
            margin: 4px 0 0;
            color: #5b6472;
            font-size: 0.98rem;
        }
        .layout {
            display: grid;
            grid-template-columns: minmax(320px, 1fr) minmax(320px, 1fr);
            gap: 16px;
            margin-bottom: 16px;
        }
        .card {
            background: #ffffff;
            border: 1px solid #dce2ec;
            border-radius: 12px;
            padding: 16px;
        }
        .card h2 {
            margin: 0 0 12px;
            font-size: 1.05rem;
            font-weight: 650;
            color: #1f2937;
        }
        label {
            display: block;
            margin-bottom: 6px;
            font-size: 0.88rem;
            font-weight: 600;
            color: #485465;
        }
        input,
        select {
            width: 100%;
            margin: 0 0 12px;
            padding: 10px 11px;
            border: 1px solid #cfd6e2;
            border-radius: 8px;
            background: #fff;
            color: #1f2937;
            font-size: 0.94rem;
        }
        input:focus,
        select:focus {
            outline: none;
            border-color: #4f76ff;
            box-shadow: 0 0 0 3px rgba(79, 118, 255, 0.14);
        }
        .checks {
            display: flex;
            gap: 18px;
            margin: 2px 0 12px;
            flex-wrap: wrap;
        }
        .checks label {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            margin: 0;
            font-weight: 500;
            color: #334155;
            cursor: pointer;
        }
        input[type="checkbox"] {
            width: auto;
            margin: 0;
            accent-color: #3f66ff;
        }
        .actions {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        button {
            border: 1px solid #cad3e4;
            border-radius: 8px;
            padding: 8px 12px;
            background: #ffffff;
            color: #1f2937;
            font-weight: 600;
            font-size: 0.9rem;
            cursor: pointer;
        }
        .btn-primary {
            background: #355dff;
            border-color: #355dff;
            color: #ffffff;
        }
        .btn-danger {
            background: #fff;
            border-color: #f0b6be;
            color: #b42318;
        }
        button:hover { filter: brightness(0.98); }
        .flash {
            margin-bottom: 16px;
            padding: 10px 12px;
            border-radius: 8px;
            border: 1px solid #c8ddff;
            background: #edf4ff;
            color: #123469;
            font-size: 0.92rem;
        }
        .table-card {
            background: #ffffff;
            border: 1px solid #dce2ec;
            border-radius: 12px;
            margin-bottom: 16px;
            overflow: hidden;
        }
        .table-head {
            padding: 14px 16px;
            border-bottom: 1px solid #e7ecf3;
            font-weight: 650;
            color: #253040;
        }
        .table-wrap { overflow-x: auto; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.92rem;
        }
        th,
        td {
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid #edf1f7;
            vertical-align: top;
        }
        th {
            background: #fafcff;
            color: #546172;
            font-size: 0.8rem;
            letter-spacing: 0.02em;
            text-transform: uppercase;
        }
        tr:last-child td { border-bottom: none; }
        code {
            white-space: pre-wrap;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 0.84rem;
            color: #334155;
        }
        .ok {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 999px;
            font-weight: 650;
            color: #1e7a3b;
            background: #e9f8ee;
        }
        .warn {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 999px;
            font-weight: 650;
            color: #a05b03;
            background: #fff5e8;
        }
        .error {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 999px;
            font-weight: 650;
            color: #b42318;
            background: #ffeceb;
        }
        .inline-form {
            display: inline-block;
            margin: 0;
            padding: 0;
            border: none;
            background: transparent;
        }
        @media (max-width: 960px) {
            .layout { grid-template-columns: 1fr; }
            .topbar {
                flex-direction: column;
                align-items: flex-start;
            }
        }
  </style>
</head>
<body>
    <div class="container">
        <div class="topbar">
            <div>
                <h1>App Admin</h1>
                <p class="subtitle">Manage always-on apps on this server and connected clients.</p>
            </div>
            <form class="inline-form" method="post" action="{{ url_for('logout') }}">
                <button type="submit">Logout</button>
            </form>
        </div>

        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="flash">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <div class="layout">
            <section class="card">
                <h2>Create Client</h2>
                <form method="post" action="{{ url_for('create_client') }}">
                    <label>Client name</label>
                    <input name="name" placeholder="client-1" required>
                    <div class="actions">
                        <button class="btn-primary" type="submit">Create Client</button>
                    </div>
                </form>
            </section>

            <section class="card">
                <h2>Add App</h2>
                <form method="post" action="{{ url_for('create_app') }}">
                    <label>Name</label>
                    <input name="name" placeholder="tid-app" required>

                    <label>Target</label>
                    <select name="target" required>
                        <option value="server">Server (this machine)</option>
                        {% for client in clients %}
                        <option value="client:{{ client['id'] }}">Client: {{ client['name'] }}</option>
                        {% endfor %}
                    </select>

                    <label>Working directory</label>
                    <input name="cwd" placeholder="/path/to/project/">

                    <label>Command</label>
                    <input name="command" placeholder="/path/to/project/.venv/bin/python app.py" required>

                    <div class="checks">
                        <label><input type="checkbox" name="always_on" checked> Always run</label>
                        <label><input type="checkbox" name="enabled" checked> Enabled</label>
                    </div>

                    <div class="actions">
                        <button class="btn-primary" type="submit">Add App</button>
                    </div>
                </form>
            </section>
        </div>

        <section class="table-card">
            <div class="table-head">Clients</div>
            <div class="table-wrap">
                <table>
                    <tr>
                        <th>ID</th><th>Name</th><th>Token</th><th>Last seen</th><th>Hostname</th><th>OS</th>
                    </tr>
                    {% for client in clients %}
                    <tr>
                        <td>{{ client['id'] }}</td>
                        <td>{{ client['name'] }}</td>
                        <td><code>{{ client['token'] }}</code></td>
                        <td>{{ client['last_seen'] or '-' }}</td>
                        <td>{{ client['hostname'] or '-' }}</td>
                        <td>{{ client['os_name'] or '-' }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
        </section>

        <section class="table-card">
            <div class="table-head">Apps</div>
            <div class="table-wrap">
                <table>
                    <tr>
                        <th>ID</th><th>Name</th><th>Target</th><th>Command</th><th>cwd</th><th>Status</th><th>PID</th><th>Actions</th>
                    </tr>
                    {% for app_item in apps %}
                    <tr>
                        <td>{{ app_item['id'] }}</td>
                        <td>{{ app_item['name'] }}</td>
                        <td>
                            {% if app_item['target_type'] == 'server' %}
                                server
                            {% else %}
                                client: {{ app_item['client_name'] or app_item['target_client_id'] }}
                            {% endif %}
                        </td>
                        <td><code>{{ app_item['command'] }}</code></td>
                        <td><code>{{ app_item['cwd'] }}</code></td>
                        <td>
                            {% if app_item['last_status'] == 'running' %}
                                <span class="ok">running</span>
                            {% elif app_item['last_status'] in ['cwd_missing', 'start_failed', 'unknown'] %}
                                <span class="error">{{ app_item['last_status'] }}</span>
                            {% else %}
                                <span class="warn">{{ app_item['last_status'] or '-' }}</span>
                            {% endif %}
                        </td>
                        <td>{{ app_item['last_pid'] or '-' }}</td>
                        <td>
                            <form class="inline-form" method="post" action="{{ url_for('toggle_app', app_id=app_item['id']) }}">
                                <button type="submit">{{ 'Disable' if app_item['enabled'] else 'Enable' }}</button>
                            </form>
                            <form class="inline-form" method="post" action="{{ url_for('delete_app', app_id=app_item['id']) }}" onsubmit="return confirm('Delete app {{ app_item['name'] }}?')">
                                <button class="btn-danger" type="submit">Delete</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
        </section>
    </div>
</body>
</html>
"""


LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin Login</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            padding: 24px;
            font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            background: linear-gradient(160deg, #f5f8ff, #eef2ff 45%, #f6f7fb 100%);
            color: #1f2937;
        }
        .panel {
            width: 100%;
            max-width: 420px;
            background: #ffffff;
            border: 1px solid #dbe2ef;
            border-radius: 14px;
            padding: 22px;
        }
        h1 {
            margin: 0;
            font-size: 1.5rem;
            letter-spacing: -0.02em;
        }
        p {
            margin: 8px 0 0;
            color: #5c6574;
            font-size: 0.95rem;
        }
        form { margin-top: 16px; }
        label {
            display: block;
            margin-bottom: 6px;
            font-size: 0.88rem;
            font-weight: 600;
            color: #485465;
        }
        input {
            width: 100%;
            margin: 0 0 12px;
            padding: 10px 11px;
            border: 1px solid #cfd6e2;
            border-radius: 8px;
            font-size: 0.94rem;
            color: #1f2937;
        }
        input:focus {
            outline: none;
            border-color: #4f76ff;
            box-shadow: 0 0 0 3px rgba(79, 118, 255, 0.14);
        }
        .flash {
            padding: 10px 12px;
            border-radius: 8px;
            margin-top: 14px;
            margin-bottom: 2px;
            border: 1px solid #c8ddff;
            background: #edf4ff;
            color: #123469;
            font-size: 0.92rem;
        }
        button {
            width: 100%;
            border: 1px solid #355dff;
            border-radius: 8px;
            padding: 10px 12px;
            background: #355dff;
            color: #fff;
            font-weight: 650;
            cursor: pointer;
        }
        button:hover { filter: brightness(0.98); }
    </style>
</head>
<body>
    <div class="panel">
        <h1>Admin Login</h1>
        <p>Sign in to manage apps and clients.</p>

        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="flash">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <form method="post" action="{{ url_for('login') }}">
            <label>Password</label>
            <input type="password" name="password" required autofocus>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""


class ManagedProcess:
    def __init__(self):
        self.process = None
        self.exit_code = None


class LocalSupervisor(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._processes = {}
        self._lock_file_handle = None

    def run(self):
        if not self._acquire_leader_lock():
            print("Supervisor already active in another process; this instance will not manage apps.")
            return

        while not self._stop_event.is_set():
            desired_apps = self._fetch_server_apps()
            desired_ids = {item["id"] for item in desired_apps}

            with self._lock:
                for app_id in list(self._processes.keys()):
                    if app_id not in desired_ids:
                        self._stop_process(app_id)
                        self._update_status(app_id, "disabled", None, None)
                        del self._processes[app_id]

            for app_item in desired_apps:
                self._ensure_running(app_item)

            time.sleep(3)

        with self._lock:
            for app_id in list(self._processes.keys()):
                self._stop_process(app_id)

        self._release_leader_lock()

    def shutdown(self):
        self._stop_event.set()

    def _acquire_leader_lock(self):
        handle = open(SUPERVISOR_LOCK_PATH, "a+")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            return False

        handle.seek(0)
        handle.truncate(0)
        handle.write(str(os.getpid()))
        handle.flush()
        self._lock_file_handle = handle
        return True

    def _release_leader_lock(self):
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

    def _get_db_last_pid(self, app_id):
        conn = get_conn()
        row = conn.execute("SELECT last_pid FROM apps WHERE id = ?", (app_id,)).fetchone()
        conn.close()
        if not row:
            return None
        return row["last_pid"]

    def _find_existing_process_pid(self, command, cwd=None):
        normalized_command = " ".join(command.split())
        if not normalized_command:
            return None

        try:
            process_lines = subprocess.check_output(["ps", "-eo", "pid=,args="], text=True)
        except Exception:
            return None

        target_cwd = os.path.realpath(cwd) if cwd else None
        for line in process_lines.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) != 2:
                continue

            pid_text, args = parts
            try:
                pid = int(pid_text)
            except ValueError:
                continue

            if pid == os.getpid():
                continue

            if normalized_command not in " ".join(args.split()):
                continue

            if target_cwd:
                try:
                    process_cwd = os.path.realpath(os.readlink(f"/proc/{pid}/cwd"))
                except Exception:
                    continue
                if process_cwd != target_cwd:
                    continue

            if self._is_pid_alive(pid):
                return pid

        return None

    def stop_app(self, app_id):
        with self._lock:
            if app_id in self._processes:
                self._stop_process(app_id)
                self._update_status(app_id, "stopped", None, None)
                del self._processes[app_id]

    def _fetch_server_apps(self):
        conn = get_conn()
        rows = conn.execute(
            """
            SELECT id, name, command, cwd
            FROM apps
            WHERE target_type = 'server' AND enabled = 1 AND always_on = 1
            ORDER BY id
            """
        ).fetchall()
        conn.close()
        return rows

    def _ensure_running(self, app_item):
        app_id = app_item["id"]
        cwd = (app_item["cwd"] or "").strip()
        command = (app_item["command"] or "").strip()

        if not command:
            self._update_status(app_id, "start_failed", None, None)
            return

        if cwd and not Path(cwd).exists():
            self._update_status(app_id, "cwd_missing", None, None)
            self.stop_app(app_id)
            return

        with self._lock:
            managed = self._processes.get(app_id)
            if managed is None:
                managed = ManagedProcess()
                self._processes[app_id] = managed

            if managed.process is None:
                existing_pid = self._get_db_last_pid(app_id)
                if existing_pid and self._is_pid_alive(existing_pid):
                    self._update_status(app_id, "running", existing_pid, None)
                    return

            if managed.process and managed.process.poll() is None:
                self._update_status(app_id, "running", managed.process.pid, None)
                return

            if managed.process and managed.process.poll() is not None:
                managed.exit_code = managed.process.returncode
                managed.process = None

            existing_running_pid = self._find_existing_process_pid(command, cwd if cwd else None)
            if existing_running_pid:
                self._update_status(app_id, "running", existing_running_pid, None)
                return

            log_path = LOG_DIR / f"server-app-{app_id}.log"
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
                managed.exit_code = None
                self._update_status(app_id, "running", managed.process.pid, None)
            except Exception:
                self._update_status(app_id, "start_failed", None, managed.exit_code)

    def _stop_process(self, app_id):
        managed = self._processes.get(app_id)
        if not managed or not managed.process:
            return
        process = managed.process
        if process.poll() is None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except ProcessLookupError:
                return
            except Exception:
                pass

            waited = 0
            while process.poll() is None and waited < 5:
                time.sleep(0.25)
                waited += 0.25

            if process.poll() is None:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except Exception:
                    pass
        if process.poll() is not None:
            managed.exit_code = process.returncode

    def _update_status(self, app_id, status, pid, exit_code):
        conn = get_conn()
        conn.execute(
            """
            UPDATE apps
            SET last_status = ?, last_pid = ?, last_exit_code = ?, updated_at = ?
            WHERE id = ?
            """,
            (status, pid, exit_code, now_iso(), app_id),
        )
        conn.commit()
        conn.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            token TEXT NOT NULL UNIQUE,
            last_seen TEXT,
            hostname TEXT,
            os_name TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target_type TEXT NOT NULL CHECK (target_type IN ('server', 'client')),
            target_client_id INTEGER,
            cwd TEXT,
            command TEXT NOT NULL,
            always_on INTEGER NOT NULL DEFAULT 1,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_status TEXT,
            last_pid INTEGER,
            last_exit_code INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(target_client_id) REFERENCES clients(id)
        )
        """
    )
    conn.commit()
    conn.close()


def token_to_client(token):
    conn = get_conn()
    row = conn.execute("SELECT * FROM clients WHERE token = ?", (token,)).fetchone()
    conn.close()
    return row


def require_admin_password_configured():
    if not _admin_password_hash:
        raise RuntimeError("Set ADMIN_PASSWORD or ADMIN_PASSWORD_HASH before starting server.")


def admin_login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped


def verify_agent_request():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ", 1)[1].strip()
    timestamp = (request.headers.get("X-Agent-Timestamp") or "").strip()
    signature = (request.headers.get("X-Agent-Signature") or "").strip()
    if not token or not timestamp or not signature:
        return None

    try:
        ts = int(timestamp)
    except ValueError:
        return None

    if abs(int(time.time()) - ts) > 90:
        return None

    body = request.get_data() or b""
    payload = request.method.upper().encode() + b"\n" + request.path.encode() + b"\n" + timestamp.encode() + b"\n" + body
    expected = hmac.new(token.encode(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None

    return token_to_client(token)


@app.get("/login")
def login_form():
    require_admin_password_configured()
    if session.get("admin_logged_in"):
        return redirect(url_for("index"))
    return render_template_string(LOGIN_TEMPLATE)


@app.post("/login")
def login():
    require_admin_password_configured()
    password = request.form.get("password") or ""
    if check_password_hash(_admin_password_hash, password):
        session.clear()
        session["admin_logged_in"] = True
        session.permanent = True
        return redirect(url_for("index"))

    flash("Invalid credentials.")
    return redirect(url_for("login_form"))


@app.post("/logout")
@admin_login_required
def logout():
    session.clear()
    return redirect(url_for("login_form"))


@app.get("/")
@admin_login_required
def index():
    conn = get_conn()
    clients = conn.execute("SELECT * FROM clients ORDER BY id").fetchall()
    apps = conn.execute(
        """
        SELECT a.*, c.name AS client_name
        FROM apps a
        LEFT JOIN clients c ON c.id = a.target_client_id
        ORDER BY a.id
        """
    ).fetchall()
    conn.close()
    return render_template_string(TEMPLATE, clients=clients, apps=apps)


@app.post("/clients")
@admin_login_required
def create_client():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Client name is required.")
        return redirect(url_for("index"))

    token = secrets.token_urlsafe(24)
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO clients (name, token, created_at) VALUES (?, ?, ?)",
            (name, token, now_iso()),
        )
        conn.commit()
        flash(f"Client '{name}' created. Token: {token}")
    except sqlite3.IntegrityError:
        flash("Client name already exists.")
    finally:
        conn.close()

    return redirect(url_for("index"))


@app.post("/apps")
@admin_login_required
def create_app():
    name = (request.form.get("name") or "").strip()
    target = (request.form.get("target") or "").strip()
    cwd = (request.form.get("cwd") or "").strip()
    command = (request.form.get("command") or "").strip()
    always_on = 1 if request.form.get("always_on") else 0
    enabled = 1 if request.form.get("enabled") else 0

    if not name or not target or not command:
        flash("Name, target, and command are required.")
        return redirect(url_for("index"))

    target_type = "server"
    target_client_id = None
    if target.startswith("client:"):
        target_type = "client"
        try:
            target_client_id = int(target.split(":", 1)[1])
        except ValueError:
            flash("Invalid target client.")
            return redirect(url_for("index"))

    conn = get_conn()
    conn.execute(
        """
        INSERT INTO apps
            (name, target_type, target_client_id, cwd, command, always_on, enabled, created_at, updated_at, last_status)
        VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (name, target_type, target_client_id, cwd, command, always_on, enabled, now_iso(), now_iso(), "pending"),
    )
    conn.commit()
    conn.close()

    flash(f"App '{name}' added.")
    return redirect(url_for("index"))


@app.post("/apps/<int:app_id>/toggle")
@admin_login_required
def toggle_app(app_id):
    conn = get_conn()
    row = conn.execute("SELECT enabled, target_type FROM apps WHERE id = ?", (app_id,)).fetchone()
    if not row:
        conn.close()
        flash("App not found.")
        return redirect(url_for("index"))

    new_enabled = 0 if row["enabled"] else 1
    new_status = "disabled" if not new_enabled else "pending"
    conn.execute(
        "UPDATE apps SET enabled = ?, last_status = ?, updated_at = ? WHERE id = ?",
        (new_enabled, new_status, now_iso(), app_id),
    )
    conn.commit()
    conn.close()

    if row["target_type"] == "server" and new_enabled == 0:
        supervisor.stop_app(app_id)

    flash("App updated.")
    return redirect(url_for("index"))


@app.post("/apps/<int:app_id>/delete")
@admin_login_required
def delete_app(app_id):
    conn = get_conn()
    row = conn.execute("SELECT target_type FROM apps WHERE id = ?", (app_id,)).fetchone()
    if row and row["target_type"] == "server":
        supervisor.stop_app(app_id)
    conn.execute("DELETE FROM apps WHERE id = ?", (app_id,))
    conn.commit()
    conn.close()

    flash("App deleted.")
    return redirect(url_for("index"))


@app.get("/api/agent/apps")
def api_agent_apps():
    client = verify_agent_request()
    if not client:
        return jsonify({"error": "unauthorized"}), 401

    conn = get_conn()
    rows = conn.execute(
        """
        SELECT id, name, cwd, command, always_on, enabled
        FROM apps
        WHERE target_type = 'client' AND target_client_id = ? AND enabled = 1
        ORDER BY id
        """,
        (client["id"],),
    ).fetchall()
    conn.execute(
        "UPDATE clients SET last_seen = ? WHERE id = ?",
        (now_iso(), client["id"]),
    )
    conn.commit()
    conn.close()

    return jsonify(
        {
            "apps": [
                {
                    "id": item["id"],
                    "name": item["name"],
                    "cwd": item["cwd"] or "",
                    "command": item["command"],
                    "always_on": bool(item["always_on"]),
                    "enabled": bool(item["enabled"]),
                }
                for item in rows
            ]
        }
    )


@app.post("/api/agent/register")
def api_agent_register():
    payload = request.get_json(silent=True) or {}
    hostname = payload.get("hostname")
    os_name = payload.get("os")

    client = verify_agent_request()
    if not client:
        return jsonify({"error": "unauthorized"}), 401

    conn = get_conn()
    conn.execute(
        "UPDATE clients SET last_seen = ?, hostname = ?, os_name = ? WHERE id = ?",
        (now_iso(), hostname, os_name, client["id"]),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "client_id": client["id"], "name": client["name"]})


@app.post("/api/agent/heartbeat")
def api_agent_heartbeat():
    payload = request.get_json(silent=True) or {}
    statuses = payload.get("statuses") or []

    client = verify_agent_request()
    if not client:
        return jsonify({"error": "unauthorized"}), 401

    conn = get_conn()
    conn.execute("UPDATE clients SET last_seen = ? WHERE id = ?", (now_iso(), client["id"]))

    for status in statuses:
        app_id = status.get("app_id")
        last_status = status.get("state")
        pid = status.get("pid")
        exit_code = status.get("last_exit")
        conn.execute(
            """
            UPDATE apps
            SET last_status = ?, last_pid = ?, last_exit_code = ?, updated_at = ?
            WHERE id = ? AND target_type = 'client' AND target_client_id = ?
            """,
            (last_status, pid, exit_code, now_iso(), app_id, client["id"]),
        )

    conn.commit()
    conn.close()
    return jsonify({"ok": True})


supervisor = LocalSupervisor()


if __name__ == "__main__":
    require_admin_password_configured()
    init_db()
    supervisor.start()
    atexit.register(supervisor.shutdown)

    host = os.environ.get("ADMIN_HOST", "0.0.0.0")
    port = int(os.environ.get("ADMIN_PORT", "8080"))
    app.run(host=host, port=port)
