"""Generate a universal base64 subscription from the validated Mihomo output."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any

from pipeline_common import (
    ROOT,
    PipelineError,
    atomic_write_text,
    fetch_text,
    is_public_server,
    load_yaml,
    read_url_list,
    validate_node_count,
)

CLASH_INPUT = "sub/merged_proxies_new.yaml"
COMPLETE_CLASH_INPUT = "sub/merged_proxies_new_2.yaml"
OUTPUT = "sub/base64.txt"
COMPLETE_OUTPUT = "sub/base64_2.txt"
FULL_OUTPUT = "sub/base64_full.txt"
SUPPORTED_SCHEMES = {
    "anytls",
    "http",
    "hysteria",
    "hysteria2",
    "hy2",
    "naive+https",
    "socks5",
    "ss",
    "trojan",
    "tuic",
    "vless",
    "vmess",
}


def quote(value: Any) -> str:
    return urllib.parse.quote(str(value or ""), safe="")


def host_port(proxy: dict[str, Any]) -> str:
    host = str(proxy["server"])
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{int(proxy['port'])}"


def query_string(items: list[tuple[str, Any]]) -> str:
    filtered = [(key, value) for key, value in items if value not in (None, "", [])]
    return urllib.parse.urlencode(filtered, doseq=True)


def fragment(name: Any) -> str:
    return f"#{quote(name)}"


def convert_vless(proxy: dict[str, Any], complete: bool = False) -> str:
    reality = proxy.get("reality-opts") or {}
    ws = proxy.get("ws-opts") or {}
    grpc = proxy.get("grpc-opts") or {}
    xhttp = proxy.get("xhttp-opts") or {}
    tls = bool(proxy.get("tls"))
    security = "reality" if reality else ("tls" if tls else "none")
    query = query_string(
        [
            ("security", security),
            (
                "encryption",
                proxy.get("encryption", "none") if complete else "none",
            ),
            ("flow", proxy.get("flow")),
            ("type", proxy.get("network", "tcp")),
            (
                "packetEncoding",
                proxy.get("packet-encoding") if complete else None,
            ),
            ("fp", proxy.get("client-fingerprint")),
            ("pbk", reality.get("public-key")),
            ("sid", reality.get("short-id")),
            ("sni", proxy.get("servername") or proxy.get("sni")),
            ("serviceName", grpc.get("grpc-service-name")),
            (
                "path",
                (xhttp.get("path") if complete else None) or ws.get("path"),
            ),
            (
                "host",
                (xhttp.get("host") if complete else None)
                or (ws.get("headers") or {}).get("Host"),
            ),
            ("mode", xhttp.get("mode") if complete else None),
            ("allowInsecure", int(bool(proxy.get("skip-cert-verify", False)))),
        ]
    )
    return f"vless://{quote(proxy.get('uuid'))}@{host_port(proxy)}?{query}{fragment(proxy['name'])}"


def convert_vmess(proxy: dict[str, Any]) -> str:
    ws = proxy.get("ws-opts") or {}
    grpc = proxy.get("grpc-opts") or {}
    network = proxy.get("network", "tcp")
    payload = {
        "v": "2",
        "ps": str(proxy["name"]),
        "add": str(proxy["server"]),
        "port": str(proxy["port"]),
        "id": str(proxy.get("uuid", "")),
        "aid": str(proxy.get("alterId", proxy.get("alter-id", 0))),
        "scy": str(proxy.get("cipher", "auto")),
        "net": str(network),
        "type": "none",
        "host": str((ws.get("headers") or {}).get("Host", "")),
        "path": str(
            grpc.get("grpc-service-name", "") if network == "grpc" else ws.get("path", "")
        ),
        "tls": "tls" if proxy.get("tls") else "",
        "sni": str(proxy.get("servername") or proxy.get("sni", "")),
        "fp": str(proxy.get("client-fingerprint", "")),
    }
    encoded = base64.b64encode(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return f"vmess://{encoded}"


def convert_ss(proxy: dict[str, Any]) -> str:
    userinfo = base64.urlsafe_b64encode(
        f"{proxy.get('cipher', '')}:{proxy.get('password', '')}".encode("utf-8")
    ).decode("ascii").rstrip("=")
    query_items: list[tuple[str, Any]] = []
    if proxy.get("plugin"):
        options = proxy.get("plugin-opts") or {}
        plugin = str(proxy["plugin"])
        if options:
            suffix = ";".join(f"{key}={value}" for key, value in options.items())
            plugin = f"{plugin};{suffix}"
        query_items.append(("plugin", plugin))
    query = query_string(query_items)
    separator = f"?{query}" if query else ""
    return f"ss://{userinfo}@{host_port(proxy)}{separator}{fragment(proxy['name'])}"


def convert_http_or_socks(proxy: dict[str, Any]) -> str:
    scheme = "socks5" if proxy["type"] in {"socks", "socks5"} else "http"
    username = proxy.get("username")
    password = proxy.get("password")
    credentials = ""
    if username not in (None, ""):
        credentials = quote(username)
        if password not in (None, ""):
            credentials += f":{quote(password)}"
        credentials += "@"
    return f"{scheme}://{credentials}{host_port(proxy)}{fragment(proxy['name'])}"


def convert_trojan(proxy: dict[str, Any]) -> str:
    ws = proxy.get("ws-opts") or {}
    grpc = proxy.get("grpc-opts") or {}
    query = query_string(
        [
            ("security", "tls"),
            ("sni", proxy.get("sni") or proxy.get("servername")),
            ("type", proxy.get("network", "tcp")),
            ("path", ws.get("path")),
            ("host", (ws.get("headers") or {}).get("Host")),
            ("serviceName", grpc.get("grpc-service-name")),
            ("allowInsecure", int(bool(proxy.get("skip-cert-verify", False)))),
        ]
    )
    return (
        f"trojan://{quote(proxy.get('password'))}@{host_port(proxy)}?{query}"
        f"{fragment(proxy['name'])}"
    )


def convert_hysteria1(proxy: dict[str, Any]) -> str:
    query = query_string(
        [
            ("auth", proxy.get("auth-str") or proxy.get("auth_str")),
            ("peer", proxy.get("sni")),
            ("insecure", int(bool(proxy.get("skip-cert-verify", False)))),
            ("upmbps", proxy.get("up")),
            ("downmbps", proxy.get("down")),
            ("alpn", (proxy.get("alpn") or [""])[0]),
            ("obfs", proxy.get("obfs")),
            ("protocol", proxy.get("protocol", "udp")),
            ("mport", proxy.get("ports")),
            ("fastopen", int(bool(proxy.get("fast-open", False)))),
        ]
    )
    return f"hysteria://{host_port(proxy)}?{query}{fragment(proxy['name'])}"


def convert_hysteria2(proxy: dict[str, Any]) -> str:
    query = query_string(
        [
            ("sni", proxy.get("sni")),
            ("insecure", int(bool(proxy.get("skip-cert-verify", False)))),
            ("obfs", proxy.get("obfs")),
            ("obfs-password", proxy.get("obfs-password")),
            ("mport", proxy.get("ports")),
        ]
    )
    return (
        f"hysteria2://{quote(proxy.get('password'))}@{host_port(proxy)}?{query}"
        f"{fragment(proxy['name'])}"
    )


def convert_tuic(proxy: dict[str, Any]) -> str:
    query = query_string(
        [
            ("sni", proxy.get("sni")),
            ("congestion_control", proxy.get("congestion-controller", "bbr")),
            ("udp_relay_mode", proxy.get("udp-relay-mode", "native")),
            ("alpn", proxy.get("alpn")),
            ("allow_insecure", int(bool(proxy.get("skip-cert-verify", False)))),
        ]
    )
    userinfo = f"{quote(proxy.get('uuid'))}:{quote(proxy.get('password'))}"
    return f"tuic://{userinfo}@{host_port(proxy)}?{query}{fragment(proxy['name'])}"


def convert_anytls(proxy: dict[str, Any]) -> str:
    query = query_string(
        [
            ("security", "tls"),
            ("sni", proxy.get("sni") or proxy.get("servername")),
            ("insecure", int(bool(proxy.get("skip-cert-verify", False)))),
        ]
    )
    return (
        f"anytls://{quote(proxy.get('password'))}@{host_port(proxy)}?{query}"
        f"{fragment(proxy['name'])}"
    )


def convert_proxy(proxy: dict[str, Any], complete: bool = False) -> str | None:
    proxy_type = str(proxy.get("type") or "").lower()
    if proxy_type == "vless":
        return convert_vless(proxy, complete=complete)
    converters = {
        "anytls": convert_anytls,
        "http": convert_http_or_socks,
        "hysteria": convert_hysteria1,
        "hysteria2": convert_hysteria2,
        "socks": convert_http_or_socks,
        "socks5": convert_http_or_socks,
        "ss": convert_ss,
        "trojan": convert_trojan,
        "tuic": convert_tuic,
        "vmess": convert_vmess,
    }
    converter = converters.get(proxy_type)
    if not converter:
        print(f"通用订阅跳过无标准分享链接的类型: {proxy_type}")
        return None
    return converter(proxy)


def parse_naive(data: str, source: str) -> str:
    config = json.loads(data)
    proxy = str(config.get("proxy") or "") if isinstance(config, dict) else ""
    if proxy.startswith("naive+https://"):
        link = proxy
    elif proxy.startswith("https://"):
        link = f"naive+https://{proxy.removeprefix('https://')}"
    else:
        raise PipelineError(f"{source} 不是有效的 Naive HTTPS 地址")
    digest = hashlib.sha256(link.encode("utf-8")).hexdigest()[:8]
    parts = urllib.parse.urlsplit(link)
    if not parts.hostname or not parts.port:
        raise PipelineError(f"{source} 缺少主机或端口")
    if not is_public_server(parts.hostname):
        raise PipelineError(f"{source} 使用非公网地址: {parts.hostname}")
    return f"{link}{fragment(f'NAIVE-{digest}')}"


def collect_naive() -> list[str]:
    links: list[str] = []
    errors: list[str] = []
    for index, url in enumerate(read_url_list("urls/naiverproxy_urls.txt"), start=1):
        source = f"naive:{index}"
        try:
            links.append(parse_naive(fetch_text(url), source))
        except Exception as exc:
            errors.append(f"{source} ({url}): {exc}")
    if errors:
        raise PipelineError("Naive 来源失败，保留旧产物:\n" + "\n".join(errors))
    return links


def existing_link_count(output: str) -> int:
    path = ROOT / output
    if not path.exists():
        return 0
    try:
        plain = base64.b64decode(path.read_text(encoding="utf-8"), validate=True).decode("utf-8")
        return len([line for line in plain.splitlines() if line.strip()])
    except Exception:
        return 0


def validate_links(links: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for link in links:
        scheme = link.split("://", 1)[0].lower() if "://" in link else ""
        if scheme not in SUPPORTED_SCHEMES:
            raise PipelineError(f"出现无效分享链接协议: {scheme or '<missing>'}")
        identity = link.split("#", 1)[0]
        if identity in seen:
            continue
        seen.add(identity)
        result.append(link)
    return result


def write_subscription(output: str, links: list[str]) -> None:
    plain = "\n".join(links)
    encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    if base64.b64decode(encoded).decode("utf-8") != plain:
        raise PipelineError(f"{output} base64 编解码自检失败")
    atomic_write_text(output, encoded)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--healthy-names",
        type=Path,
        help="check_nodes.py 生成的健康节点名称 JSON；未提供时不更新 base64.txt",
    )
    parser.add_argument(
        "--complete-healthy-names",
        type=Path,
        help="完整参数 YAML 的健康节点名称 JSON；未提供时不更新 base64_2.txt",
    )
    return parser.parse_args()


def load_proxy_links(
    input_path: str, complete: bool = False
) -> list[tuple[str, str]]:
    config = load_yaml(input_path)
    proxies = config.get("proxies")
    if not isinstance(proxies, list):
        raise PipelineError(f"{input_path} 缺少 proxies")
    return [
        (str(proxy["name"]), link)
        for proxy in proxies
        if isinstance(proxy, dict)
        if (link := convert_proxy(proxy, complete=complete))
    ]


def load_healthy_names(path: Path) -> set[str]:
    try:
        healthy_value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PipelineError(f"无法读取健康节点名单: {exc}") from exc
    if not isinstance(healthy_value, list) or not all(
        isinstance(name, str) for name in healthy_value
    ):
        raise PipelineError("健康节点名单必须是字符串数组")
    return set(healthy_value)


def write_healthy_subscription(
    output: str,
    proxy_links: list[tuple[str, str]],
    healthy_path: Path,
    label: str,
) -> None:
    healthy_names = load_healthy_names(healthy_path)
    healthy_links = validate_links(
        [link for name, link in proxy_links if name in healthy_names]
    )
    if len(healthy_links) < 20:
        raise PipelineError(
            f"{label}测活节点仅 {len(healthy_links)} 个，低于安全阈值 20；{output} 保持不变"
        )
    old_healthy_count = existing_link_count(output)
    write_subscription(output, healthy_links)
    print(
        f"{label}测活订阅生成完成: {len(healthy_links)} 个节点"
        f"（旧 {old_healthy_count}）"
    )


def main() -> None:
    args = parse_args()
    proxy_links = load_proxy_links(CLASH_INPUT)
    full_links = validate_links([link for _, link in proxy_links] + collect_naive())
    old_full_count = existing_link_count(FULL_OUTPUT)
    validate_node_count(len(full_links), old_full_count, "base64_full")
    write_subscription(FULL_OUTPUT, full_links)
    print(f"全量通用订阅生成完成: {len(full_links)} 个节点（旧 {old_full_count}）")

    if not args.healthy_names:
        print("未提供健康节点名单，base64.txt 保持不变")
    else:
        write_healthy_subscription(
            OUTPUT, proxy_links, args.healthy_names, ""
        )

    if not args.complete_healthy_names:
        print("未提供完整参数健康节点名单，base64_2.txt 保持不变")
    else:
        complete_proxy_links = load_proxy_links(
            COMPLETE_CLASH_INPUT, complete=True
        )
        write_healthy_subscription(
            COMPLETE_OUTPUT,
            complete_proxy_links,
            args.complete_healthy_names,
            "完整参数版",
        )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"通用订阅生成失败: {exc}", file=sys.stderr)
        sys.exit(1)
