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
MCP_IMAGE = "cpg-nuclei-mcp"
MCP_PORT = 8265
MCP_DOCKER_DIR = ROOT / "harness" / "mcp"
DEFAULT_MCP_TEMPLATE = ROOT / "templates" / "mcp-server-unauth-tools-list.yaml"


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


def _ensure_mcp_template(template: Path) -> None:
    if template.is_file():
        return
    template.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [
            "cargo",
            "run",
            "-p",
            "cpg_nuclei_core",
            "--bin",
            "cpg_nuclei_cli",
            "--",
            "--render-spec",
            "MCP-TOOLS-LIST",
            str(template),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if proc.returncode != 0 or not template.is_file():
        raise RuntimeError(
            f"failed to render MCP template: {proc.stdout}\n{proc.stderr}"
        )


def _ensure_mcp_container() -> str:
    build = subprocess.run(
        ["docker", "build", "-t", MCP_IMAGE, str(MCP_DOCKER_DIR)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if build.returncode != 0:
        raise RuntimeError(f"docker build MCP fixture failed: {build.stderr}")

    name = f"cpg-nuclei-mcp-{uuid.uuid4().hex[:8]}"
    run = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "-p",
            f"{MCP_PORT}:{MCP_PORT}",
            MCP_IMAGE,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if run.returncode != 0:
        raise RuntimeError(f"docker run MCP fixture failed: {run.stderr}")

    for _ in range(60):
        if _port_open("127.0.0.1", MCP_PORT):
            return name
        time.sleep(0.1)

    subprocess.run(["docker", "stop", name], capture_output=True, check=False)
    raise RuntimeError(f"MCP fixture failed to bind 127.0.0.1:{MCP_PORT}")


def _stop_container(name: str) -> None:
    subprocess.run(["docker", "stop", name], capture_output=True, check=False)


def _parse_nuclei_output(stdout: str, stderr: str) -> tuple[bool, list[str], list[str]]:
    hits: list[str] = []
    extracted: list[str] = []
    for line in (stdout + "\n" + stderr).splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                for key in ("extracted-results", "extractor-results"):
                    val = payload.get(key)
                    if isinstance(val, list):
                        extracted.extend(str(v) for v in val)
                    elif val is not None:
                        extracted.append(str(val))
        if line.startswith("[") and "]" in line:
            hits.append(line)
        if " matches found" in line.lower() and not line.lower().startswith("0 "):
            return True, hits, extracted
    return bool(hits), hits, extracted


def run_scan(
    template: Path,
    target: str,
    *,
    image: str = DEFAULT_IMAGE,
    start_fixture: bool = True,
    start_mcp: bool = False,
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
    mcp_container: str | None = None
    if start_mcp:
        start_fixture = False
        mcp_container = _ensure_mcp_container()
    elif start_fixture and host in ("127.0.0.1", "localhost") and not _port_open(host, port):
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
            "-nc",
        ]
    )
    if start_mcp:
        cmd.append("-jsonl")
    else:
        cmd.append("-silent")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    finally:
        if fixture_proc is not None:
            fixture_proc.terminate()
            try:
                fixture_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                fixture_proc.kill()
        if mcp_container is not None:
            _stop_container(mcp_container)

    matched, hits, extracted = _parse_nuclei_output(proc.stdout, proc.stderr)
    verdict = "TP" if matched else "TN"
    report = {
        "template": str(template),
        "target": target,
        "verdict": verdict,
        "exit_code": proc.returncode,
        "hits": hits,
        "extracted": extracted,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS / f"{template.stem}-{verdict.lower()}.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CPG-Nuclei Docker closed-loop runner")
    parser.add_argument("--template", type=Path, required=False)
    parser.add_argument("--target", default=None)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run fixture-tp.yaml against local fixture (expects TP)",
    )
    parser.add_argument(
        "--mcp",
        action="store_true",
        help="Run MCP tools/list template against harness/mcp Docker fixture",
    )
    args = parser.parse_args(argv)

    if not shutil.which("docker"):
        print("docker not found on PATH", file=sys.stderr)
        return 2

    template = args.template
    start_mcp = False
    if args.self_test:
        template = ROOT / "templates" / "fixture-tp.yaml"
        target = args.target or "http://127.0.0.1:5000"
    elif args.mcp:
        template = template or DEFAULT_MCP_TEMPLATE
        _ensure_mcp_template(template)
        target = args.target or f"http://127.0.0.1:{MCP_PORT}"
        start_mcp = True
    elif template is None:
        parser.error("--template is required unless --self-test or --mcp is set")
    else:
        target = args.target or "http://127.0.0.1:5000"

    report = run_scan(
        template,
        target,
        image=args.image,
        start_mcp=start_mcp,
    )
    print(json.dumps(report, indent=2))
    return 0 if report["verdict"] in ("TP", "TN") else 1


if __name__ == "__main__":
    raise SystemExit(main())
