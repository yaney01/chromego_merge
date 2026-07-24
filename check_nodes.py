"""Validate Mihomo configuration and optionally perform real proxy handshakes.

Scheduled GitHub-hosted runs use validation only. Run with ``--filter`` on a
China-side host to remove nodes that fail both HTTPS targets for every round.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml

from pipeline_common import MIN_NODES, PipelineError, ROOT, atomic_write_text

DEFAULT_CONFIG = ROOT / "sub" / "merged_proxies_new.yaml"
TARGETS = ("https://cp.cloudflare.com", "https://www.gstatic.com/generate_204")
CONTROLLER = "127.0.0.1:19090"
API_BASE = f"http://{CONTROLLER}"


def request_json(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    return data if isinstance(data, dict) else {}


def validate_config(mihomo: str, config: Path) -> None:
    result = subprocess.run(
        [mihomo, "-t", "-f", str(config)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise PipelineError(f"Mihomo 配置校验失败: {detail[-1000:]}")
    print("Mihomo 配置校验通过")


def make_probe_config(config: dict[str, Any], directory: Path) -> Path:
    probe = dict(config)
    probe["mixed-port"] = 17890
    probe["allow-lan"] = False
    probe["external-controller"] = CONTROLLER
    probe["secret"] = ""
    probe["mode"] = "global"
    dns = dict(probe.get("dns") or {})
    dns["enable"] = False
    dns.pop("listen", None)
    probe["dns"] = dns
    tun = dict(probe.get("tun") or {})
    tun["enable"] = False
    probe["tun"] = tun
    path = directory / "probe.yaml"
    path.write_text(
        yaml.safe_dump(probe, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    return path


def wait_for_api(process: subprocess.Popen[str], timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise PipelineError(f"Mihomo 启动失败: {output[-1000:]}")
        try:
            request_json(f"{API_BASE}/version", 1)
            return
        except Exception:
            time.sleep(0.25)
    raise PipelineError("等待 Mihomo API 超时")


def delay_test(name: str, target: str, timeout_ms: int) -> bool:
    encoded_name = urllib.parse.quote(name, safe="")
    query = urllib.parse.urlencode({"url": target, "timeout": timeout_ms})
    url = f"{API_BASE}/proxies/{encoded_name}/delay?{query}"
    try:
        data = request_json(url, timeout_ms / 1000 + 2)
        return int(data.get("delay", 0)) > 0
    except (OSError, ValueError, urllib.error.HTTPError):
        return False


def ensure_probe_network(timeout_ms: int) -> None:
    if not any(delay_test("DIRECT", target, timeout_ms) for target in TARGETS):
        raise PipelineError("探针本身无法访问两个 HTTPS 目标，拒绝删除任何节点")


def probe_nodes(
    proxies: list[dict[str, Any]],
    rounds: int,
    timeout_ms: int,
    workers: int,
) -> set[str]:
    names = [str(proxy["name"]) for proxy in proxies]
    successes: set[str] = set()
    ensure_probe_network(timeout_ms)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for round_number in range(1, rounds + 1):
            futures = {
                executor.submit(delay_test, name, target, timeout_ms): (name, target)
                for name in names
                for target in TARGETS
                if name not in successes
            }
            for future in concurrent.futures.as_completed(futures):
                name, _ = futures[future]
                if future.result():
                    successes.add(name)
            print(f"真实握手第 {round_number}/{rounds} 轮: 已成功 {len(successes)}/{len(names)}")
    return successes


def filter_config(config: dict[str, Any], healthy: set[str]) -> dict[str, Any]:
    proxies = config.get("proxies")
    if not isinstance(proxies, list):
        raise PipelineError("配置缺少 proxies")
    kept = [
        proxy
        for proxy in proxies
        if isinstance(proxy, dict) and str(proxy.get("name")) in healthy
    ]
    required = max(MIN_NODES, int(len(proxies) * 0.1))
    if len(kept) < required:
        raise PipelineError(
            f"健康检查结果异常: 保留 {len(kept)}/{len(proxies)}，最低要求 {required}"
        )
    config["proxies"] = kept
    valid_names = {str(proxy["name"]) for proxy in kept}
    for group in config.get("proxy-groups", []):
        if not isinstance(group, dict) or not isinstance(group.get("proxies"), list):
            continue
        group["proxies"] = [
            name
            for name in group["proxies"]
            if name in valid_names or name in {"自动选择", "DIRECT", "REJECT"}
        ]
    return config


def run_filter(
    mihomo: str,
    config_path: Path,
    rounds: int,
    timeout_ms: int,
    workers: int,
) -> None:
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("proxies"), list):
        raise PipelineError("配置不是有效的 Mihomo YAML")
    original_count = len(config["proxies"])
    with tempfile.TemporaryDirectory(prefix="mihomo-probe-") as temporary:
        directory = Path(temporary)
        probe_config = make_probe_config(config, directory)
        process = subprocess.Popen(
            [mihomo, "-d", str(directory), "-f", str(probe_config)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_for_api(process)
            healthy = probe_nodes(config["proxies"], rounds, timeout_ms, workers)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    filtered = filter_config(config, healthy)
    rendered = yaml.safe_dump(filtered, sort_keys=False, allow_unicode=True)
    atomic_write_text(config_path.relative_to(ROOT), rendered)
    print(f"健康检查完成: 保留 {len(filtered['proxies'])}/{original_count} 个节点")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--mihomo", default=os.environ.get("MIHOMO_BIN", "mihomo"))
    parser.add_argument("--filter", action="store_true")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--timeout-ms", type=int, default=8000)
    parser.add_argument("--workers", type=int, default=24)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = args.config.resolve()
    if ROOT not in config.parents:
        raise PipelineError("配置文件必须位于仓库内")
    if args.rounds < 2:
        raise PipelineError("至少需要 2 轮，避免单次抖动误删")
    validate_config(args.mihomo, config)
    if args.filter:
        run_filter(args.mihomo, config, args.rounds, args.timeout_ms, args.workers)
        validate_config(args.mihomo, config)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"节点检查失败: {exc}", file=sys.stderr)
        sys.exit(1)
