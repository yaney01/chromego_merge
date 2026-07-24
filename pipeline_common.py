"""Shared helpers for the subscription generation pipeline."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

import yaml

ROOT = Path(__file__).resolve().parent
USER_AGENT = "chromego-merge/2.0 (+https://github.com/yaney01/chromego_merge)"
FETCH_ATTEMPTS = 3
FETCH_TIMEOUT = 20
MIN_NODES = 20
MIN_RETAIN_RATIO = 0.5


class PipelineError(RuntimeError):
    pass


def read_url_list(path: str | Path) -> list[str]:
    url_path = ROOT / path
    try:
        lines = url_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PipelineError(f"无法读取来源列表 {url_path}: {exc}") from exc
    urls = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not urls:
        raise PipelineError(f"来源列表为空: {url_path}")
    return urls


def fetch_text(url: str) -> str:
    last_error: Exception | None = None
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
                if response.status != 200:
                    raise PipelineError(f"HTTP {response.status}")
                data = response.read()
            if not data:
                raise PipelineError("响应为空")
            return data.decode("utf-8-sig")
        except Exception as exc:
            last_error = exc
            if attempt < FETCH_ATTEMPTS:
                delay = 2 ** (attempt - 1)
                print(f"抓取失败，{delay}s 后重试 ({attempt}/{FETCH_ATTEMPTS}): {url}: {exc}")
                time.sleep(delay)
    raise PipelineError(f"抓取失败 ({FETCH_ATTEMPTS} 次): {url}: {last_error}")


def collect_sources(
    url_file: str | Path,
    parser: Callable[[str, str], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, url in enumerate(read_url_list(url_file), start=1):
        source = f"{Path(url_file).stem}:{index}"
        try:
            parsed = parser(fetch_text(url), source)
            if not parsed:
                raise PipelineError("没有解析出节点")
            nodes.extend(parsed)
            print(f"{source}: {len(parsed)} 个节点")
        except Exception as exc:
            errors.append(f"{source} ({url}): {exc}")
    if errors:
        joined = "\n".join(f"- {item}" for item in errors)
        raise PipelineError(f"{url_file} 有来源失败，保留旧产物:\n{joined}")
    return nodes


def split_server_port(value: Any, default_port: int = 443) -> tuple[str, int, str | None]:
    raw = str(value or "").strip()
    if not raw:
        raise PipelineError("server 为空")

    ports: str
    if raw.startswith("["):
        host, separator, rest = raw[1:].partition("]")
        if not separator:
            raise PipelineError(f"IPv6 地址格式错误: {raw}")
        ports = rest.lstrip(":") or str(default_port)
    elif raw.count(":") == 1:
        host, ports = raw.rsplit(":", 1)
    elif ":" in raw:
        host, ports = raw, str(default_port)
    else:
        host, ports = raw, str(default_port)

    first_port = ports.split(",", 1)[0].split("-", 1)[0].strip()
    try:
        port = int(first_port)
    except ValueError as exc:
        raise PipelineError(f"端口格式错误: {raw}") from exc
    if not 1 <= port <= 65535:
        raise PipelineError(f"端口超出范围: {raw}")
    port_range = ports if ports != str(port) else None
    return host.strip(), port, port_range


def is_public_server(server: Any) -> bool:
    host = str(server or "").strip().strip("[]")
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        lowered = host.rstrip(".").lower()
        if (
            lowered == "localhost"
            or lowered.endswith((".localhost", ".local", ".internal", ".lan"))
            or "." not in lowered
        ):
            return False
        return True


def _clean_name(value: Any, proxy_type: str) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()
    text = re.sub(r"\s+", " ", text)
    return (text or proxy_type.upper())[:64]


def proxy_signature(proxy: dict[str, Any]) -> str:
    payload = {key: value for key, value in proxy.items() if key != "name"}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def normalize_proxies(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for original in proxies:
        if not isinstance(original, dict):
            continue
        proxy = dict(original)
        proxy_type = str(proxy.get("type") or "").strip().lower()
        server = str(proxy.get("server") or "").strip().strip("[]")
        try:
            port = int(proxy.get("port"))
        except (TypeError, ValueError):
            print(f"跳过端口无效节点: {proxy.get('name', '<unnamed>')}")
            continue
        if not proxy_type or not server or not 1 <= port <= 65535:
            print(f"跳过字段不完整节点: {proxy.get('name', '<unnamed>')}")
            continue
        if not is_public_server(server):
            print(f"跳过非公网地址节点: {server}:{port}")
            continue
        proxy["type"] = proxy_type
        proxy["server"] = server
        proxy["port"] = port
        signature = proxy_signature(proxy)
        if signature in seen:
            continue
        seen.add(signature)
        proxy["name"] = f"{_clean_name(proxy.get('name'), proxy_type)}-{signature[:8]}"
        normalized.append(proxy)
    return normalized


def load_yaml(path: str | Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PipelineError(f"无法解析 YAML {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PipelineError(f"YAML 顶层必须是对象: {path}")
    return value


def existing_yaml_node_count(path: str | Path) -> int:
    target = ROOT / path
    if not target.exists():
        return 0
    try:
        value = yaml.safe_load(target.read_text(encoding="utf-8"))
        proxies = value.get("proxies", []) if isinstance(value, dict) else []
        return len(proxies) if isinstance(proxies, list) else 0
    except Exception:
        return 0


def validate_node_count(new_count: int, old_count: int, label: str) -> None:
    required = MIN_NODES
    if old_count:
        required = max(required, int(old_count * MIN_RETAIN_RATIO))
    if new_count < required:
        raise PipelineError(
            f"{label} 节点数异常: 新 {new_count}，旧 {old_count}，最低要求 {required}；保留旧产物"
        )


def atomic_write_text(path: str | Path, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
