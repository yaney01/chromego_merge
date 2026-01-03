import yaml
import json
import urllib.request
import logging
import geoip2.database
import socket
import re

logging.basicConfig(level=logging.ERROR)

# ============ 安全工具函数 ============

def safe_yaml_load(text):
    try:
        data = yaml.safe_load(text)
        return data
    except Exception:
        return None


def safe_json_load(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def get_physical_location(address: str) -> str:
    if not address:
        return "Unknown"
    try:
        address = re.sub(r":.*", "", address)
        ip = socket.gethostbyname(address)
    except Exception:
        return "Unknown"

    try:
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        resp = reader.city(ip)
        country = resp.country.name or "Unknown"
        city = resp.city.name or ""
        return f"{country}_{city}"
    except Exception:
        return "Unknown"


def process_urls(file_path, handler):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            urls = [i.strip() for i in f if i.strip()]
    except Exception as e:
        logging.error(f"Read url file failed: {file_path} {e}")
        return

    for idx, url in enumerate(urls):
        try:
            resp = urllib.request.urlopen(url, timeout=15)
            raw = resp.read().decode("utf-8", errors="ignore")
            handler(raw, idx)
        except Exception as e:
            logging.error(f"Error processing URL {url}: {e}")


# ============ 全局结果 ============

merged_proxies = []

# ============ 处理 Clash 订阅 ============

def process_clash(data, index):
    cfg = safe_yaml_load(data)
    if not isinstance(cfg, dict):
        return

    proxies = cfg.get("proxies")
    if not isinstance(proxies, list):
        return

    for i, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        server = p.get("server", "")
        ptype = p.get("type", "unknown")
        loc = get_physical_location(server)
        p["name"] = f"{loc}_{ptype}_{index}_{i}"
        merged_proxies.append(p)

# ============ 处理 quick_urls.txt（anytls）===========

def process_quick(data, index):
    cfg = safe_yaml_load(data)
    if not isinstance(cfg, dict):
        return

    proxies = cfg.get("proxies")
    if not isinstance(proxies, list):
        return

    for i, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        if p.get("type") != "anytls":
            continue

        server = p.get("server", "")
        loc = get_physical_location(server)
        p["name"] = f"{loc}_anytls_{index}_{i}"
        merged_proxies.append(p)

# ============ hysteria ============

def process_hysteria(data, index):
    js = safe_json_load(data)
    if not isinstance(js, dict):
        return

    auth = js.get("auth_str")
    server_port = js.get("server", "")
    if not auth or ":" not in server_port:
        return

    server, port = server_port.split(":", 1)
    try:
        port = int(port.split(",")[0])
    except Exception:
        return

    proxy = {
        "name": f"{get_physical_location(server)}_hysteria_{index}",
        "type": "hysteria",
        "server": server,
        "port": port,
        "auth_str": auth,
        "sni": js.get("server_name", ""),
        "protocol": js.get("protocol", ""),
        "alpn": [js["alpn"]] if js.get("alpn") else [],
        "skip-cert-verify": js.get("insecure", 0),
    }
    merged_proxies.append(proxy)

# ============ hysteria2 ============

def process_hysteria2(data, index):
    js = safe_json_load(data)
    if not isinstance(js, dict):
        return

    auth = js.get("auth")
    server_port = js.get("server", "")
    if not auth or ":" not in server_port:
        return

    server, port = server_port.split(":", 1)
    try:
        port = int(port.split(",")[0])
    except Exception:
        return

    tls = js.get("tls", {})

    proxy = {
        "name": f"{get_physical_location(server)}_hysteria2_{index}",
        "type": "hysteria2",
        "server": server,
        "port": port,
        "password": auth,
        "sni": tls.get("sni", ""),
        "skip-cert-verify": tls.get("insecure", 0),
    }
    merged_proxies.append(proxy)

# ============ xray / vless reality ============

def process_xray(data, index):
    js = safe_json_load(data)
    if not isinstance(js, dict):
        return

    outbounds = js.get("outbounds", [])
    if not outbounds:
        return

    ob = outbounds[0]
    if ob.get("protocol") != "vless":
        return

    settings = ob.get("settings", {})
    vnext = settings.get("vnext", [])
    if not vnext:
        return

    node = vnext[0]
    users = node.get("users", [])
    if not users:
        return

    user = users[0]
    stream = ob.get("streamSettings", {})
    reality = stream.get("realitySettings", {})

    proxy = {
        "name": f"{get_physical_location(node.get('address',''))}_vless_{index}",
        "type": "vless",
        "server": node.get("address", ""),
        "port": node.get("port", 0),
        "uuid": user.get("id", ""),
        "flow": user.get("flow", ""),
        "tls": 1,
        "udp": 1,
        "client-fingerprint": reality.get("fingerprint", ""),
        "servername": reality.get("serverName", ""),
        "network": stream.get("network", ""),
        "reality-opts": {
            "public-key": reality.get("publicKey", ""),
            "short-id": reality.get("shortId", ""),
        },
    }
    merged_proxies.append(proxy)

# ============ proxy-groups ============

def update_proxy_groups(cfg, proxies):
    for g in cfg.get("proxy-groups", []):
        if not isinstance(g, dict):
            continue
        if g.get("proxies") is None:
            g["proxies"] = [p["name"] for p in proxies if "name" in p]
        else:
            exist = set(g["proxies"])
            for p in proxies:
                n = p.get("name")
                if n and n not in exist:
                    g["proxies"].append(n)

# ============ 主流程 ============

process_urls("./urls/clash_urls.txt", process_clash)
process_urls("./urls/quick_urls.txt", process_quick)
process_urls("./urls/hysteria_urls.txt", process_hysteria)
process_urls("./urls/hysteria2_urls.txt", process_hysteria2)
process_urls("./urls/xray_urls.txt", process_xray)

with open("./templates/clash_template.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f) or {}

config.setdefault("proxies", [])
config["proxies"].extend(merged_proxies)
update_proxy_groups(config, merged_proxies)

with open("./sub/merged_proxies_new.yaml", "w", encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True, sort_keys=False)

print(f"Merged meta done, total proxies: {len(merged_proxies)}")
