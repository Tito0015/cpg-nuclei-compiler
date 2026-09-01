"""Run Nuclei in Docker against a template and target; write TP/TN JSON report."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "harness" / "reports"
DEFAULT_IMAGE = "projectdiscovery/nuclei:latest"


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _ensure_fixture(host: str, port: int) -> subprocess.Popen[bytes] | None:
    if _port_open(host, port):
        return None
    proc = subprocess.Popen(
        [sys.executable, "-m", "harness.fixture_server", "--host", host, "--port", str(port)],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(30):
        if _port_open(host, port):
            return proc
        time.sleep(0.1)
    proc.kill()
    raise RuntimeError(f"fixture server failed to bind {host}:{port}")


def _parse_nuclei_output(stdout: str, stderr: str) -> tuple[bool, list[str]]:
    hits: list[str] = []
    for line in (stdout + "\n" + stderr).splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("[") and "]" in line:
            hits.append(line)
        if " matches found" in line.lower() and not line.lower().startswith("0 "):
            return True, hits
    return bool(hits), hits


def run_scan(
    template: Path,
    target: str,
    *,
    image: str = DEFAULT_IMAGE,
    start_fixture: bool = True,
) -> dict:
    if not template.is_file():
        raise FileNotFoundError(template)

    host = "127.0.0.1"
    port = 5000
    if target.startswith("http://"):
        rest = target.removeprefix("http://")
        if ":" in rest:
            host, port_s = rest.split(":", 1)
            port = int(port_s.split("/", 1)[0])
        else:
            host = rest.split("/", 1)[0]

    fixture_proc: subprocess.Popen[bytes] | None = None
    if start_fixture and host in ("127.0.0.1", "localhost") and not _port_open(host, port):
        fixture_proc = _ensure_fixture(host, port)

    container = f"cpg-nuclei-{uuid.uuid4().hex[:8]}"
    scan_url = target
    if platform.system() == "Windows" and "127.0.0.1" in target:
        scan_url = target.replace("127.0.0.1", "host.docker.internal")

    cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        container,
    ]
    if platform.system() != "Windows":
        cmd.extend(["--network", "host"])
    cmd.extend(
        [
            "-v",
            f"{template.resolve().parent}:/templates:ro",
            image,
            "-t",
            f"/templates/{template.name}",
            "-u",
            scan_url,
            "-silent",
            "-nc",
        ]
    )

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    finally:
        if fixture_proc is not None:
            fixture_proc.terminate()
            try:
                fixture_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                fixture_proc.kill()

    matched, hits = _parse_nuclei_output(proc.stdout, proc.stderr)
    verdict = "TP" if matched else "TN"
    report = {
        "template": str(template),
        "target": target,
        "verdict": verdict,
        "exit_code": proc.returncode,
        "hits": hits,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS / f"{template.stem}-{verdict.lower()}.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CPG-Nuclei Docker closed-loop runner")
    parser.add_argument("--template", type=Path, required=False)
    parser.add_argument("--target", default="http://127.0.0.1:5000")
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run fixture-tp.yaml against local fixture (expects TP)",
    )
    args = parser.parse_args(argv)

    if not shutil.which("docker"):
        print("docker not found on PATH", file=sys.stderr)
        return 2

    template = args.template
    if args.self_test:
        template = ROOT / "templates" / "fixture-tp.yaml"
    elif template is None:
        parser.error("--template is required unless --self-test is set")

    report = run_scan(template, args.target, image=args.image)
    print(json.dumps(report, indent=2))
    return 0 if report["verdict"] in ("TP", "TN") else 1


if __name__ == "__main__":
    raise SystemExit(main())
