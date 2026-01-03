import yaml
import json
import urllib.request
import logging
import geoip2.database
import socket
import re

# 安全获取物理位置（国家_城市）
def get_physical_location(address):
    try:
        address = re.sub(":.*", "", address)
        ip_address = socket.gethostbyname(address)
    except Exception:
        return "Unknown"

    try:
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        response = reader.city(ip_address)
        country = response.country.name or "Unknown"
        city = response.city.name or ""
        return f"{country}_{city}"
    except Exception:
        return "Unknown"

# 通用处理 URL 列表
def process_urls(url_file, processor):
    try:
        with open(url_file, "r") as f:
            urls = f.read().splitlines()
    except Exception as e:
        logging.error(f"Error reading URL file {url_file}: {e}")
        return

    for index, url in enumerate(urls):
        if not url:
            continue
        try:
            resp = urllib.request.urlopen(url)
            data = resp.read().decode("utf-8")
            processor(data, index)
        except Exception as e:
            logging.error(f"Error processing URL {url}: {e}")

# 处理 Clash 订阅
def process_clash(data, index):
    try:
        content = yaml.safe_load(data)
        if not isinstance(content, dict):
            return

        proxies = content.get("proxies", [])
        if not isinstance(proxies, list):
            return

        for i, proxy in enumerate(proxies):
            server = proxy.get("server", "")
            ptype = proxy.get("type", "")
            loc = get_physical_location(server)
            proxy["name"] = f"{loc}_{ptype}_{index}{i+1}"
            merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error in process_clash: {e}")

# 处理 shadowtls
def process_sb(data, index):
    try:
        js = json.loads(data)
        # 多层安全取值
        out0 = js.get("outbounds", [{}])[0]
        out1 = js.get("outbounds", [{}])[1]
        method = out0.get("method", "")
        password = out0.get("password", "")
        server = out1.get("server", "")
        server_port = out1.get("server_port", "")
        tls = out1.get("tls", {})
        server_name = tls.get("server_name", "")
        shadowtls_password = out1.get("password", "")
        version = out1.get("version", 0)

        loc = get_physical_location(server)
        name = f"{loc}_shadowtls_{index}"

        proxy = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": server_port,
            "cipher": method,
            "password": password,
            "plugin": "shadow-tls",
            "plugin-opts": {
                "host": server_name,
                "password": shadowtls_password,
                "version": int(version),
            },
        }
        merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error in process_sb: {e}")

# 处理 hysteria
def process_hysteria(data, index):
    try:
        js = json.loads(data)
        auth = js.get("auth_str", "")
        server_ports = js.get("server", "")
        parts = server_ports.split(":")
        if len(parts) < 2:
            return
        server, port_str = parts[0], parts[1]
        port_int = int(port_str.split(",")[0])

        insecure = js.get("insecure", 0)
        server_name = js.get("server_name", "")
        alpn = js.get("alpn", "")
        protocol = js.get("protocol", "")

        loc = get_physical_location(server)
        name = f"{loc}_hysteria_{index}"

        proxy = {
            "name": name,
            "type": "hysteria",
            "server": server,
            "port": port_int,
            "auth_str": auth,
            "protocol": protocol,
            "sni": server_name,
            "skip-cert-verify": insecure,
            "alpn": [alpn] if alpn else [],
        }
        merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error in process_hysteria: {e}")

# 处理 hysteria2
def process_hysteria2(data, index):
    try:
        js = json.loads(data)
        auth = js.get("auth", "")
        server_ports = js.get("server", "")
        parts = server_ports.split(":")
        if len(parts) < 2:
            return
        server, port_str = parts[0], parts[1]
        port_int = int(port_str.split(",")[0])

        tls = js.get("tls", {})
        insecure = tls.get("insecure", 0)
        sni = tls.get("sni", "")

        loc = get_physical_location(server)
        name = f"{loc}_hysteria2_{index}"

        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": port_int,
            "password": auth,
            "sni": sni,
            "skip-cert-verify": insecure,
        }
        merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error in process_hysteria2: {e}")

# 处理 XRay/VLESS/VMess
def process_xray(data, index):
    try:
        js = json.loads(data)
        out0 = js.get("outbounds", [{}])[0]
        protocol = out0.get("protocol", "")

        if protocol == "vless":
            settings = out0.get("settings", {})
            vnext = settings.get("vnext", [])
            if not vnext:
                return
            node = vnext[0]
            server = node.get("address", "")
            port = node.get("port", 0)
            users = node.get("users", [])
            user = users[0] if users else {}
            uuid = user.get("id", "")
            flow = user.get("flow", "")

            stream = out0.get("streamSettings", {})
            reality = stream.get("realitySettings", {})

            publicKey = reality.get("publicKey", "")
            shortId = reality.get("shortId", "")
            serverName = reality.get("serverName", "")
            fingerprint = reality.get("fingerprint", "")

            loc = get_physical_location(server)
            name = f"{loc}_vless_{index}"

            proxy = {
                "name": name,
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": uuid,
                "network": stream.get("network", ""),
                "tls": 1,
                "udp": 1,
                "flow": flow,
                "client-fingerprint": fingerprint,
                "servername": serverName,
                "reality-opts": {
                    "public-key": publicKey,
                    "short-id": shortId,
                },
            }
            merged_proxies.append(proxy)

        # you can add more protocols here like shadowsocks if needed
    except Exception as e:
        logging.error(f"Error in process_xray: {e}")

# 更新 proxy-groups
def update_proxy_groups(cfg, merged):
    for group in cfg.get("proxy-groups", []):
        if not isinstance(group, dict):
            continue
        proxies = group.get("proxies")
        if proxies is None:
            group["proxies"] = [p["name"] for p in merged]
        else:
            existing = set(proxies)
            for p in merged:
                pname = p.get("name")
                if pname and pname not in existing:
                    group["proxies"].append(pname)

# ========= 主流程 =========

merged_proxies = []

process_urls("./urls/clash_urls.txt", process_clash)
process_urls("./urls/hysteria_urls.txt", process_hysteria)
process_urls("./urls/hysteria2_urls.txt", process_hysteria2)
process_urls("./urls/xray_urls.txt", process_xray)

# 读取模板配置
with open("./templates/clash_template.yaml", "r", encoding="utf-8") as f:
    config_data = yaml.safe_load(f) or {}

# 合并 proxies
config_data.setdefault("proxies", [])
for p in merged_proxies:
    config_data["proxies"].append(p)

# 更新 proxy-groups
update_proxy_groups(config_data, merged_proxies)

# 写出
with open("./sub/merged_proxies_new.yaml", "w", encoding="utf-8") as f:
    yaml.dump(config_data, f, sort_keys=False, allow_unicode=True)

print("Merged meta file written.")
