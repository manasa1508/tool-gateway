#!/usr/bin/env python3
"""Black-box tests of the built binary using synthetic data and local processes."""
import argparse
import json
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def assert_result(response):
    assert "result" in response, response
    return response["result"]


def assert_denied(response):
    assert "error" in response, response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    binary = str(Path(parser.parse_args().binary).resolve())
    with tempfile.TemporaryDirectory(prefix="tool-gateway-e2e-") as directory:
        root = Path(directory)
        policy = root / "policy.json"
        subprocess.run([binary, "demo-policy", "--out", str(policy)], cwd=root,
                       check=True, capture_output=True)
        process = subprocess.Popen([binary, "stdio", "--policy", str(policy)],
                                   cwd=root, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        seq = 0

        def rpc(method, params=None, notification=False):
            nonlocal seq
            seq += 1
            request = {"jsonrpc": "2.0", "method": method}
            if not notification:
                request["id"] = str(seq)
            if params is not None:
                request["params"] = params
            process.stdin.write(json.dumps(request).encode() + b"\n")
            process.stdin.flush()
            if notification:
                return None
            assert select.select([process.stdout], [], [], 5)[0], "stdio response timed out"
            line = process.stdout.readline()
            assert line, "stdio process exited"
            response = json.loads(line)
            assert response["id"] == str(seq), response
            return response

        try:
            init = assert_result(rpc("initialize", {"protocolVersion": "2025-11-25"}))
            assert "io.toolgateway/task" in init["_meta"]
            rpc("notifications/initialized", notification=True)
            tools = assert_result(rpc("tools/list"))["tools"]
            read = next(t["name"] for t in tools if t["name"].endswith("_read_note"))
            send = next(t["name"] for t in tools if t["name"].endswith("_send_message"))
            assert_result(rpc("tools/call", {"name": send, "arguments": {"message": "hello"}}))
            synthetic = "ghp_" + "A" * 36
            assert_denied(rpc("tools/call", {"name": send, "arguments": {"message": synthetic}}))
            assert_result(rpc("tools/call", {"name": read, "arguments": {}}))
            assert_denied(rpc("tools/call", {"name": send, "arguments": {"message": "internal data"}}))
            assert_denied(rpc("sampling/createMessage", {}))
        finally:
            process.stdin.close()
            process.wait(timeout=5)
            if process.returncode:
                raise AssertionError(process.stderr.read().decode())
        verification = subprocess.run([binary, "verify-audit", "--file", str(root / "audit.local.jsonl")],
                                      check=True, capture_output=True)
        assert json.loads(verification.stdout)["valid"]
        assert synthetic not in (root / "audit.local.jsonl").read_text(), "audit leaked secret"

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        config = json.loads(policy.read_text())
        config["listen"] = f"127.0.0.1:{port}"
        config["audit_path"] = str(root / "http-audit.local.jsonl")
        policy.write_text(json.dumps(config))
        token = secrets.token_hex(32)
        environment = dict(os.environ, TOOL_GATEWAY_TOKEN=token)
        process = subprocess.Popen([binary, "serve", "--policy", str(policy)], cwd=root,
                                   env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        base = f"http://127.0.0.1:{port}"
        try:
            for _ in range(100):
                try:
                    with urllib.request.urlopen(base + "/healthz", timeout=0.1):
                        break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.025)
            else:
                raise AssertionError("HTTP gateway failed to start")
            headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json",
                       "Accept": "application/json, text/event-stream"}

            def post(message):
                request = urllib.request.Request(base + "/mcp", data=json.dumps(message).encode(),
                                                 headers=headers, method="POST")
                with urllib.request.urlopen(request, timeout=5) as response:
                    body = response.read()
                    return response.headers, json.loads(body) if body else None, response.status

            response_headers, response, _ = post({"jsonrpc": "2.0", "id": "1", "method": "initialize",
                                                  "params": {"protocolVersion": "2025-11-25"}})
            assert_result(response)
            headers["Mcp-Session-Id"] = response_headers["Mcp-Session-Id"]
            headers["MCP-Protocol-Version"] = "2025-11-25"
            _, _, status = post({"jsonrpc": "2.0", "method": "notifications/initialized"})
            assert status == 202
            _, response, _ = post({"jsonrpc": "2.0", "id": "2", "method": "tools/list"})
            assert len(assert_result(response)["tools"]) == 2
            try:
                urllib.request.urlopen(urllib.request.Request(base + "/metrics"), timeout=5)
                raise AssertionError("unauthenticated metrics request succeeded")
            except urllib.error.HTTPError as error:
                assert error.code == 401
        finally:
            process.terminate()
            _, stderr = process.communicate(timeout=10)
            assert process.returncode == 0, stderr.decode()
    print("PASS: real stdio + HTTP mediation, DLP, data-flow denial, audit verification, graceful shutdown")


if __name__ == "__main__":
    main()
