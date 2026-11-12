"""Bounded subprocess execution, logs and cancellation."""
import os
import signal
import subprocess
import time

from pathlib import Path
from .core import utc_now, sha256


def stop_process(process):
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.kill()
    process.wait()


def execute(name, command, output, timeout, cancel=None, env=None):
    logs = output / "logs"
    logs.mkdir(exist_ok=True)
    stdout_path, stderr_path = logs / f"{name}.stdout.txt", logs / f"{name}.stderr.txt"
    record = {"step": name, "command": command, "started_utc": utc_now(),
              "stdout_log": stdout_path.relative_to(output).as_posix(),
              "stderr_log": stderr_path.relative_to(output).as_posix(), "exit_code": None}
    if Path(command[0]).is_file():
        record["executable_sha256"] = sha256(Path(command[0]))
    start = time.monotonic()
    environment = os.environ.copy()
    environment.update({"PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"})
    if env:
        environment.update(env)
    try:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL,
                                       shell=False, cwd=output, env=environment,
                                       start_new_session=os.name != "nt",
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            while process.poll() is None:
                if cancel and cancel.is_set():
                    record["status"] = "cancelled"
                    stop_process(process)
                    break
                if time.monotonic() - start >= timeout:
                    record["status"] = "timeout"
                    stop_process(process)
                    break
                time.sleep(0.1)
            record["exit_code"] = process.returncode
            record.setdefault("status", "success" if process.returncode == 0 else "failed")
    except OSError as exc:
        record.update(status="failed", error=str(exc))
    record["duration_seconds"] = round(time.monotonic() - start, 3)
    record["completed_utc"] = utc_now()
    return record
