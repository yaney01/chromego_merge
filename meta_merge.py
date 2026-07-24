"""Build the Mihomo subscription from all configured upstream sources."""

from __future__ import annotations

import json
import re
import sys
from typing import Any

import yaml

from pipeline_common import (
    PipelineError,
    atomic_write_text,
    collect_sources,
    existing_yaml_node_count,
    load_yaml,
    normalize_proxies,
    split_server_port,
    validate_node_count,
)

OUTPUT = "sub/merged_proxies_new.yaml"


def parse_clash(data: str, source: str) -> list[dict[str, Any]]:
    content = yaml.safe_load(data)
    if not isinstance(content, dict) or not isinstance(content.get("proxies"), list):
        raise PipelineError("不是有效的 Clash/Mihomo 配置")
    result: list[dict[str, Any]] = []
    for index, proxy in enumerate(content["proxies"], start=1):
        if not isinstance(proxy, dict):
            continue
        node = dict(proxy)
        node["name"] = node.get("name") or f"{source}-{index}"
        result.append(node)
    return result


def _seconds(value: Any, default: int = 30) -> int:
    match = re.search(r"\d+", str(value or ""))
    return int(match.group()) if match else default


def _parse_hysteria1(config: dict[str, Any], source: str) -> dict[str, Any]:
    server, port, ports = split_server_port(config.get("server"))
    auth = config.get("auth_str") or config.get("auth-str") or config.get("auth")
    if not auth:
        raise PipelineError("Hysteria 1 缺少 auth_str")
    node: dict[str, Any] = {
        "name": source,
        "type": "hysteria",
        "server": server,
        "port": port,
        "auth-str": str(auth),
        "protocol": config.get("protocol", "udp"),
        "up": config.get("up_mbps", config.get("up", 100)),
        "down": config.get("down_mbps", config.get("down", 100)),
        "sni": config.get("server_name") or config.get("sni", ""),
        "skip-cert-verify": bool(config.get("insecure", False)),
        "fast-open": bool(config.get("fast_open", False)),
    }
    if ports:
        node["ports"] = ports
    if config.get("obfs"):
        node["obfs"] = config["obfs"]
    alpn = config.get("alpn")
    if alpn:
        node["alpn"] = [alpn] if isinstance(alpn, str) else alpn
    for source_key, target_key in (
        ("recv_window_conn", "recv-window-conn"),
        ("recv_window", "recv-window"),
        ("disable_mtu_discovery", "disable_mtu_discovery"),
    ):
        if source_key in config:
            node[target_key] = config[source_key]
    return node


def _parse_hysteria2(config: dict[str, Any], source: str) -> dict[str, Any]:
    server, port, ports = split_server_port(config.get("server"))
    auth = config.get("auth") or config.get("password")
    if not auth:
        raise PipelineError("Hysteria 2 缺少 auth")
    tls = config.get("tls") if isinstance(config.get("tls"), dict) else {}
    bandwidth = config.get("bandwidth") if isinstance(config.get("bandwidth"), dict) else {}
    node: dict[str, Any] = {
        "name": source,
        "type": "hysteria2",
        "server": server,
        "port": port,
        "password": str(auth),
        "sni": tls.get("sni") or config.get("sni", ""),
        "skip-cert-verify": bool(tls.get("insecure", config.get("insecure", False))),
    }
    if ports:
        node["ports"] = ports
    if bandwidth.get("up"):
        node["up"] = bandwidth["up"]
    if bandwidth.get("down"):
        node["down"] = bandwidth["down"]
    transport = config.get("transport") if isinstance(config.get("transport"), dict) else {}
    udp = transport.get("udp") if isinstance(transport.get("udp"), dict) else {}
    if udp.get("hopInterval"):
        node["hop-interval"] = _seconds(udp["hopInterval"])
    obfs = config.get("obfs")
    if isinstance(obfs, dict):
        obfs_type = obfs.get("type")
        if obfs_type:
            node["obfs"] = obfs_type
            settings = obfs.get(obfs_type)
            if isinstance(settings, dict) and settings.get("password"):
                node["obfs-password"] = settings["password"]
    elif obfs:
        node["obfs"] = obfs
        if config.get("obfs-password"):
            node["obfs-password"] = config["obfs-password"]
    return node


def parse_hysteria_auto(data: str, source: str) -> list[dict[str, Any]]:
    config = json.loads(data)
    if not isinstance(config, dict):
        raise PipelineError("Hysteria 配置顶层不是对象")
    h1_markers = {"auth_str", "auth-str", "up_mbps", "down_mbps", "server_name"}
    h2_markers = {"bandwidth", "transport", "tls"}
    if h1_markers.intersection(config):
        return [_parse_hysteria1(config, source)]
    if h2_markers.intersection(config) and ("auth" in config or "password" in config):
        return [_parse_hysteria2(config, source)]
    raise PipelineError("无法按内容识别 Hysteria 版本")


def _singbox_tls(outbound: dict[str, Any], node: dict[str, Any]) -> None:
    tls = outbound.get("tls") if isinstance(outbound.get("tls"), dict) else {}
    if not tls.get("enabled"):
        return
    node["tls"] = True
    if tls.get("server_name"):
        node["servername"] = tls["server_name"]
        node["sni"] = tls["server_name"]
    if tls.get("insecure") is not None:
        node["skip-cert-verify"] = bool(tls["insecure"])
    utls = tls.get("utls") if isinstance(tls.get("utls"), dict) else {}
    if utls.get("fingerprint"):
        node["client-fingerprint"] = utls["fingerprint"]
    reality = tls.get("reality") if isinstance(tls.get("reality"), dict) else {}
    if reality.get("enabled"):
        node["reality-opts"] = {
            "public-key": reality.get("public_key", ""),
            "short-id": reality.get("short_id", ""),
        }


def _singbox_transport(outbound: dict[str, Any], node: dict[str, Any]) -> None:
    transport = outbound.get("transport")
    if not isinstance(transport, dict) or not transport.get("type"):
        return
    network = transport["type"]
    node["network"] = network
    if network == "grpc":
        node["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
    elif network == "ws":
        node["ws-opts"] = {
            "path": transport.get("path", "/"),
            "headers": transport.get("headers", {}),
        }


def _convert_singbox_outbound(outbound: dict[str, Any], source: str) -> dict[str, Any] | None:
    proxy_type = str(outbound.get("type") or "").lower()
    if proxy_type in {"direct", "block", "dns", "selector", "urltest"}:
        return None
    server = outbound.get("server")
    port = outbound.get("server_port")
    if proxy_type == "tuic":
        node: dict[str, Any] = {
            "name": outbound.get("tag") or source,
            "type": "tuic",
            "server": server,
            "port": port,
            "uuid": outbound.get("uuid", ""),
            "password": outbound.get("password", ""),
            "congestion-controller": outbound.get("congestion_control", "bbr"),
            "udp-relay-mode": "native",
        }
        tls = outbound.get("tls") if isinstance(outbound.get("tls"), dict) else {}
        node["sni"] = tls.get("server_name", "")
        node["skip-cert-verify"] = bool(tls.get("insecure", False))
        if tls.get("alpn"):
            node["alpn"] = tls["alpn"]
        return node
    if proxy_type == "vless":
        node = {
            "name": outbound.get("tag") or source,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": outbound.get("uuid", ""),
            "flow": outbound.get("flow", ""),
            "network": "tcp",
            "udp": True,
        }
        _singbox_tls(outbound, node)
        _singbox_transport(outbound, node)
        return node
    raise PipelineError(f"暂不支持的 sing-box outbound: {proxy_type}")


def parse_singbox(data: str, source: str) -> list[dict[str, Any]]:
    config = json.loads(data)
    outbounds = config.get("outbounds") if isinstance(config, dict) else None
    if not isinstance(outbounds, list):
        raise PipelineError("sing-box 配置缺少 outbounds")
    result = []
    for outbound in outbounds:
        if isinstance(outbound, dict):
            node = _convert_singbox_outbound(outbound, source)
            if node:
                result.append(node)
    return result


def parse_xray(data: str, source: str) -> list[dict[str, Any]]:
    config = json.loads(data)
    outbounds = config.get("outbounds") if isinstance(config, dict) else None
    if not isinstance(outbounds, list):
        raise PipelineError("Xray 配置缺少 outbounds")
    result: list[dict[str, Any]] = []
    for outbound in outbounds:
        if not isinstance(outbound, dict) or outbound.get("protocol") != "vless":
            continue
        vnext = (outbound.get("settings") or {}).get("vnext") or []
        if not vnext or not vnext[0].get("users"):
            continue
        endpoint = vnext[0]
        user = endpoint["users"][0]
        stream = outbound.get("streamSettings") or {}
        network = stream.get("network", "tcp")
        security = stream.get("security", "none")
        reality = stream.get("realitySettings") or {}
        tls = stream.get("tlsSettings") or {}
        node: dict[str, Any] = {
            "name": outbound.get("tag") or source,
            "type": "vless",
            "server": endpoint.get("address"),
            "port": endpoint.get("port"),
            "uuid": user.get("id", ""),
            "network": network,
            "udp": True,
            "tls": security in {"tls", "reality"},
            "servername": reality.get("serverName") or tls.get("serverName", ""),
            "client-fingerprint": reality.get("fingerprint")
            or tls.get("fingerprint", "chrome"),
            "skip-cert-verify": bool(tls.get("allowInsecure", False)),
        }
        if user.get("flow"):
            node["flow"] = user["flow"]
        if security == "reality":
            node["reality-opts"] = {
                "public-key": reality.get("publicKey", ""),
                "short-id": reality.get("shortId", ""),
            }
        if network == "grpc":
            node["grpc-opts"] = {
                "grpc-service-name": (stream.get("grpcSettings") or {}).get("serviceName", "")
            }
        elif network == "ws":
            ws = stream.get("wsSettings") or {}
            node["ws-opts"] = {"path": ws.get("path", "/"), "headers": ws.get("headers", {})}
        result.append(node)
    return result


def parse_shadowquic(data: str, source: str) -> list[dict[str, Any]]:
    config = yaml.safe_load(data)
    outbound = config.get("outbound") if isinstance(config, dict) else None
    if not isinstance(outbound, dict) or outbound.get("type") != "shadowquic":
        raise PipelineError("不是 ShadowQUIC 客户端配置")
    server, port, _ = split_server_port(outbound.get("addr"))
    node: dict[str, Any] = {
        "name": source,
        "type": "shadowquic",
        "server": server,
        "port": port,
        "username": outbound.get("username", ""),
        "password": outbound.get("password", ""),
        "sni": outbound.get("server-name", ""),
        "alpn": outbound.get("alpn", ["h3"]),
        "zero-rtt": bool(outbound.get("zero-rtt", False)),
        "congestion-controller": outbound.get("congestion-control", "bbr"),
        "udp-over-stream": bool(outbound.get("over-stream", False)),
    }
    return [node]


def update_groups(config: dict[str, Any], proxies: list[dict[str, Any]]) -> None:
    groups = config.get("proxy-groups")
    if not isinstance(groups, list):
        raise PipelineError("模板缺少 proxy-groups")
    names = [proxy["name"] for proxy in proxies]
    for group in groups:
        if not isinstance(group, dict):
            continue
        if group.get("name") == "自动选择":
            group["proxies"] = names
        elif group.get("name") == "节点选择":
            group["proxies"] = ["自动选择", "DIRECT", *names]


def main() -> None:
    proxies: list[dict[str, Any]] = []
    proxies += collect_sources("urls/clash_urls.txt", parse_clash)
    proxies += collect_sources("urls/quick_urls.txt", parse_clash)
    proxies += collect_sources("urls/hysteria_urls.txt", parse_hysteria_auto)
    proxies += collect_sources("urls/hysteria2_urls.txt", parse_hysteria_auto)
    proxies += collect_sources("urls/sb_urls.txt", parse_singbox)
    proxies += collect_sources("urls/ss_urls.txt", parse_shadowquic)
    proxies += collect_sources("urls/xray_urls.txt", parse_xray)

    proxies = normalize_proxies(proxies)
    old_count = existing_yaml_node_count(OUTPUT)
    validate_node_count(len(proxies), old_count, "Clash")

    config = load_yaml("templates/clash_template.yaml")
    config["proxies"] = proxies
    update_groups(config, proxies)
    rendered = yaml.safe_dump(config, sort_keys=False, allow_unicode=True)
    parsed = yaml.safe_load(rendered)
    if not isinstance(parsed, dict) or len(parsed.get("proxies", [])) != len(proxies):
        raise PipelineError("生成后的 Clash YAML 自检失败")
    atomic_write_text(OUTPUT, rendered)
    print(f"Clash 聚合完成: {len(proxies)} 个节点（旧 {old_count}）")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Clash 聚合失败: {exc}", file=sys.stderr)
        sys.exit(1)
