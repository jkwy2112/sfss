#!/usr/bin/env python3
"""End-to-end smoke test: two single-purpose SFSS systems over real HTTP.

System 1 (SFSS_DEPLOYMENT_MODE=inbound):  green upload -> scan -> release -> red download.
System 2 (SFSS_DEPLOYMENT_MODE=outbound): red upload -> classify -> approve -> green download.

Verifies each system serves its own workflow end to end and rejects the other
workflow's routes with 404. Uses temporary data directories and ephemeral
ports; cleans up on exit. Exit code 0 means all checks passed.

Usage:
    scripts/smoke_split.py [--repo /path/to/sfss]
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def api(port, method, path, token=None, zone=None, filename=None, body=b"", expect=None):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body if method in ("POST", "PUT") else None, method=method)
    if token: request.add_header("Authorization", f"Bearer {token}")
    if zone: request.add_header("X-SFSS-Zone", zone)
    if filename: request.add_header("X-Filename", filename)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            status, payload = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, payload = error.code, error.read()
    if expect is not None:
        assert status == expect, f"{method} {path} -> {status} (expected {expect}): {payload[:200]}"
    return status, payload


def wait_healthy(port, mode, process):
    for _ in range(60):
        try:
            status, _ = api(port, "GET", "/health")
            if status == 200: return
        except Exception:
            pass
        if process.poll() is not None:
            output = process.stdout.read().decode(errors="replace")
            raise SystemExit(f"{mode} system exited early:\n{output}")
        time.sleep(0.3)
    raise SystemExit(f"{mode} system on port {port} never became healthy")


def start_system(repo, mode, port, data_dir):
    env = {**os.environ, "PYTHONPATH": f"{repo}/src",
           "SFSS_DEPLOYMENT_MODE": mode, "SFSS_ENVIRONMENT": "development",
           "SFSS_DATA_DIR": str(data_dir)}
    process = subprocess.Popen([sys.executable, "-m", "sfss.server", "--port", str(port)],
                               cwd=repo, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    wait_healthy(port, mode, process)
    return process


def wait_state(port, path, token, zone, match, extract, attempts=50):
    for _ in range(attempts):
        status, body = api(port, "GET", path, token, zone)
        if status == 200 and match(json.loads(body)):
            return extract(json.loads(body))
        time.sleep(0.2)
    raise SystemExit(f"timed out waiting for state at {path}: {status} {body[:200]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    repo = Path(args.repo).resolve()
    base = Path(tempfile.mkdtemp(prefix="sfss-smoke-split-"))
    port_in, port_out = free_port(), free_port()
    results = []
    inbound = outbound = None
    try:
        inbound = start_system(repo, "inbound", port_in, base / "inbound")
        outbound = start_system(repo, "outbound", port_out, base / "outbound")

        # ---- System 1 (inbound): personal-space green upload, red download ----
        payload = b"green zone netlist"
        status, body = api(port_in, "POST", "/v1/objects", "dev-alice",
                           "green", "netlist.txt", payload, expect=202)
        object_id = json.loads(body)["id"]
        object_id = wait_state(
            port_in, f"/v1/objects/{object_id}", "dev-alice", "red",
            lambda record: record["state"] == "released", lambda record: record["id"])
        status, downloaded = api(port_in, "GET",
                                 f"/v1/objects/{object_id}/download",
                                 "dev-alice", "red", expect=200)
        assert downloaded == payload, "inbound payload mismatch"
        results.append(f"System1 inbound({port_in}): green upload -> release -> red download OK")

        api(port_in, "GET", "/v1/outbound", "dev-alice", "red", expect=404)
        api(port_in, "PUT", "/v1/admin/outbound-policy", "dev-admin",
            body=json.dumps({"enabled": True}).encode(), expect=404)
        results.append(f"System1 inbound({port_in}): outbound routes rejected with 404")

        # ---- System 2 (outbound): red upload, platform approver, green download ----
        api(port_out, "PUT", "/v1/admin/outbound-policy", "dev-admin",
            body=json.dumps({"enabled": True, "approval_provider": "local",
                             "allowed_classifications": ["GENERAL"],
                             "approval_timeout_hours": 24,
                             "download_ttl_hours": 24}).encode(), expect=200)
        payload = b"red zone handoff text"
        status, body = api(port_out, "POST", "/v1/outbound", "dev-alice",
                           "red", "handoff.txt", payload, expect=202)
        transfer_id = json.loads(body)["id"]
        transfer_id = wait_state(
            port_out, "/v1/outbound", "dev-alice", "red",
            lambda data: any(row["id"] == transfer_id and row["state"] == "pending_approval"
                             for row in data["transfers"]),
            lambda data: transfer_id)
        status, body = api(port_out, "POST",
                           f"/v1/outbound/{transfer_id}/decision", "dev-admin",
                           body=json.dumps({"approved": True, "comment": "smoke"}).encode(),
                           expect=200)
        assert json.loads(body)["state"] == "released_to_green"
        api(port_out, "GET",
           f"/v1/outbound/{transfer_id}/download", "dev-reader", "green", expect=404)
        status, downloaded = api(port_out, "GET",
                                 f"/v1/outbound/{transfer_id}/download",
                                 "dev-alice", "green", expect=200)
        assert downloaded == payload, "outbound payload mismatch"
        results.append(f"System2 outbound({port_out}): red upload -> approve -> green download OK")

        api(port_out, "GET", "/v1/objects", "dev-alice", "green", expect=404)
        api(port_out, "POST", "/v1/objects", "dev-alice", "green",
            "x.txt", b"x", expect=404)
        results.append(f"System2 outbound({port_out}): inbound routes rejected with 404")

        for port, mode in ((port_in, "inbound"), (port_out, "outbound")):
            _, body = api(port, "GET", "/v1/me", "dev-admin", expect=200)
            assert json.loads(body)["deployment_mode"] == mode
            _, body = api(port, "GET", "/ready", expect=200)
            assert json.loads(body)["deployment_mode"] == mode
        results.append("Both systems report their deployment_mode")
    finally:
        for process in (inbound, outbound):
            if process and process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill()
        shutil.rmtree(base, ignore_errors=True)

    for line in results: print("PASS:", line)
    print("ALL SMOKE TESTS PASSED")


if __name__ == "__main__":
    main()
