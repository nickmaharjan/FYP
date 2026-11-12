"""Loopback-only case dashboard with a per-session bearer token."""
import hmac
import json
import mimetypes
import re
import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .config import doctor, load_config
from .core import utc_now
from .demo import create_demo
from .pipeline import analyze


class CaseManager:
    def __init__(self, root, config):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.config = config
        self.jobs = {}
        self.lock = threading.Lock()

    def start(self, data, demo=False):
        with self.lock:
            if any(job["status"] == "running" for job in self.jobs.values()):
                raise ValueError("An analysis is already running. Wait or cancel it before starting another.")
            identifier = uuid.uuid4().hex
            output = self.root / identifier
            case_id = str(data.get("case_id") or ("SYNTHETIC-DEMO" if demo else "Untitled case"))
            job = {"id": identifier, "case_id": case_id, "status": "running", "started_utc": utc_now(), "messages": [], "cancel": threading.Event()}
            self.jobs[identifier] = job

        def work():
            try:
                if demo:
                    evidence = create_demo(self.root / (identifier + "-fixture"))
                    data.update({key: str(value) for key, value in evidence.items()})
                options = {key: data[key] for key in ("yara_rules", "iocs", "tools", "mvt_mode", "kind") if data.get(key) is not None}
                for key in ("timeout", "image_offset", "max_rows"):
                    if key in data:
                        options[key] = int(data[key])
                result = analyze(data["evidence"], output, case_id, config=self.config,
                                 progress=lambda message: job["messages"].append(message), cancel=job["cancel"], **options)
                job["status"] = result["status"]
            except Exception as exc:
                job.update(status="failed", error=str(exc))
        threading.Thread(target=work, daemon=True).start()
        return {"id": identifier, "case_id": case_id, "status": "running"}

    def get(self, identifier):
        if not re.fullmatch(r"[0-9a-f]{32}", identifier):
            raise KeyError(identifier)
        result_path = self.root / identifier / "results.json"
        if result_path.is_file():
            result = json.loads(result_path.read_text(encoding="utf-8"))
            return {"id": identifier, "case_id": result["case_id"], "status": result["status"], "result": result}
        if identifier in self.jobs:
            return {key: value for key, value in self.jobs[identifier].items() if key != "cancel"}
        raise KeyError(identifier)

    def list(self):
        identifiers = set(self.jobs) | {p.name for p in self.root.iterdir() if re.fullmatch(r"[0-9a-f]{32}", p.name)}
        results = []
        for identifier in identifiers:
            try:
                case = self.get(identifier)
                result = case.get("result", case)
                results.append({"id": identifier, **{key: result.get(key) for key in ("case_id", "status", "metrics", "started_utc")}})
            except (KeyError, OSError, ValueError):
                continue
        return sorted(results, key=lambda c: c.get("started_utc") or "", reverse=True)


def make_server(root, config=None, port=8765):
    manager = CaseManager(root, load_config(config) if not isinstance(config, dict) else config)
    token = secrets.token_urlsafe(32)
    static = Path(__file__).parent / "static"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, status, body, content_type="application/json"):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def allowed(self):
            expected_hosts = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
            if self.headers.get("Host") not in expected_hosts:
                self.send(403, {"error": "Invalid host"})
                return False
            origin = self.headers.get("Origin")
            if origin and origin not in {"http://" + host for host in expected_hosts}:
                self.send(403, {"error": "Cross-origin requests are not allowed"})
                return False
            if self.path.startswith("/api/") and not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token):
                self.send(401, {"error": "Open the dashboard URL printed in the terminal, including its session token."})
                return False
            return True

        def do_GET(self):
            if not self.allowed():
                return
            path = urlparse(self.path).path
            try:
                if path in ("/", "/index.html"):
                    self.send(200, (static / "index.html").read_bytes(), "text/html; charset=utf-8")
                elif path in ("/static/app.js", "/static/style.css"):
                    file = static / path.rsplit("/", 1)[1]
                    self.send(200, file.read_bytes(), "text/javascript; charset=utf-8" if file.suffix == ".js" else "text/css; charset=utf-8")
                elif path == "/api/tools":
                    self.send(200, doctor(manager.config))
                elif path == "/api/cases":
                    self.send(200, manager.list())
                elif path.startswith("/api/cases/"):
                    self.send(200, manager.get(path.rsplit("/", 1)[1]))
                elif path.startswith("/api/download/"):
                    parts = path.split("/")
                    if len(parts) != 5 or parts[4] not in {"report.html", "results.json", "timeline.csv", "manifest.json", "audit.jsonl"}:
                        raise KeyError(path)
                    manager.get(parts[3])
                    file = manager.root / parts[3] / parts[4]
                    self.send(200, file.read_bytes(), mimetypes.guess_type(file.name)[0] or "application/octet-stream")
                else:
                    raise KeyError(path)
            except (KeyError, FileNotFoundError):
                self.send(404, {"error": "Case or file not found"})

        def do_POST(self):
            if not self.allowed():
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                if not 0 <= length <= 65536:
                    raise ValueError("Request too large")
                data = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(data, dict):
                    raise ValueError("Expected a JSON object")
                if self.path in ("/api/cases", "/api/demo"):
                    if self.path == "/api/cases" and not data.get("evidence"):
                        raise ValueError("Evidence path is required")
                    self.send(202, manager.start(data, demo=self.path.endswith("demo")))
                elif self.path.startswith("/api/cancel/"):
                    identifier = self.path.rsplit("/", 1)[1]
                    manager.jobs[identifier]["cancel"].set()
                    self.send(200, {"status": "cancellation_requested"})
                else:
                    self.send(404, {"error": "Unknown action"})
            except (ValueError, TypeError, KeyError) as exc:
                self.send(400, {"error": str(exc)})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.manager, server.token = manager, token
    return server


def serve(root, config=None, port=8765):
    server = make_server(root, config, port)
    print(f"Mobile DF dashboard: http://127.0.0.1:{server.server_port}/#{server.token}", flush=True)
    print("Press Ctrl+C to stop. Keep this terminal open while using the dashboard.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        for job in server.manager.jobs.values():
            job["cancel"].set()
    finally:
        server.server_close()
