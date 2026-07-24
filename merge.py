"""Generate a universal base64 subscription from the validated Mihomo output."""

from __future__ import annotations

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
    load_yaml,
    read_url_list,
    validate_node_count,
)

CLASH_INPUT = "sub/merged_proxies_new.yaml"
OUTPUT = "sub/base64.txt"
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


def convert_vless(proxy: dict[str, Any]) -> str:
    reality = proxy.get("reality-opts") or {}
    ws = proxy.get("ws-opts") or {}
    grpc = proxy.get("grpc-opts") or {}
    tls = bool(proxy.get("tls"))
    security = "reality" if reality else ("tls" if tls else "none")
    query = query_string(
        [
            ("security", security),
            ("encryption", "none"),
            ("flow", proxy.get("flow")),
            ("type", proxy.get("network", "tcp")),
            ("fp", proxy.get("client-fingerprint")),
            ("pbk", reality.get("public-key")),
            ("sid", reality.get("short-id")),
            ("sni", proxy.get("servername") or proxy.get("sni")),
            ("serviceName", grpc.get("grpc-service-name")),
            ("path", ws.get("path")),
            ("host", (ws.get("headers") or {}).get("Host")),
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


def convert_proxy(proxy: dict[str, Any]) -> str | None:
    proxy_type = str(proxy.get("type") or "").lower()
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
        "vless": convert_vless,
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


def existing_link_count() -> int:
    path = ROOT / OUTPUT
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


def main() -> None:
    config = load_yaml(CLASH_INPUT)
    proxies = config.get("proxies")
    if not isinstance(proxies, list):
        raise PipelineError("Clash 输出缺少 proxies")
    links = [link for proxy in proxies if isinstance(proxy, dict) if (link := convert_proxy(proxy))]
    links.extend(collect_naive())
    links = validate_links(links)

    old_count = existing_link_count()
    validate_node_count(len(links), old_count, "base64")
    plain = "\n".join(links)
    encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    if base64.b64decode(encoded).decode("utf-8") != plain:
        raise PipelineError("base64 编解码自检失败")
    atomic_write_text(OUTPUT, encoded)
    print(f"通用订阅生成完成: {len(links)} 个节点（旧 {old_count}）")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"通用订阅生成失败: {exc}", file=sys.stderr)
        sys.exit(1)
