import yaml
import json
import urllib.request
import logging
import geoip2.database
import socket
import re


# 提取节点
def process_urls(url_file, processor):
    try:
        with open(url_file, "r") as file:
            urls = file.read().splitlines()

        for index, url in enumerate(urls):
            try:
                # 修复：加 UA 头避免 403，并加超时
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    },
                )
                response = urllib.request.urlopen(req, timeout=15)
                data = response.read().decode("utf-8")
                processor(data, index)
            except Exception as e:
                logging.error(f"Error processing URL {url}: {e}")
    except Exception as e:
        logging.error(f"Error reading file {url_file}: {e}")


# 修复：拆分 server:port，兼容 [ipv6]:port、裸 ipv6、ipv4:port、domain、无端口
def split_server_port(server_ports, default_port=443):
    server_ports = str(server_ports).strip()
    if server_ports.startswith("["):
        # [2001:db8::1]:443,444
        host, _, rest = server_ports[1:].partition("]")
        rest = rest.lstrip(":")
        ports = rest if rest else str(default_port)
    elif server_ports.count(":") == 1:
        # ipv4:port 或 domain:port
        host, ports = server_ports.split(":")
    elif ":" not in server_ports:
        # 无端口
        host, ports = server_ports, str(default_port)
    else:
        # 裸 IPv6，无端口
        host, ports = server_ports, str(default_port)

    ports_slt = ports.split(",")
    port = int(ports_slt[0])
    mport = ports_slt[1] if len(ports_slt) > 1 else port
    return host, port, mport


# 提取clash节点
def process_clash(data, index):
    content = yaml.safe_load(data)
    proxies = content.get("proxies", [])
    for i, proxy in enumerate(proxies):
        location = get_physical_location(proxy["server"])
        proxy["name"] = f"{location}_{proxy['type']}_{index}{i+1}"
    merged_proxies.extend(proxies)


def get_physical_location(address):
    # 修复：正确剥离端口，兼容 IPv6（原正则会把裸 IPv6 截成 '2a14'）
    address = str(address).strip()
    if address.startswith("["):
        address = address[1:].split("]")[0]
    elif address.count(":") == 1:
        address = address.split(":")[0]
    # 多冒号且无方括号 = 裸 IPv6，原样保留

    try:
        ip_address = socket.gethostbyname(address)
    except socket.gaierror:
        ip_address = address

    try:
        reader = geoip2.database.Reader(
            "GeoLite2-City.mmdb"
        )  # 这里的路径需要指向你自己的数据库文件
        response = reader.city(ip_address)
        country = response.country.name
        city = response.city.name
        return f"{country}_{city}"
    except Exception as e:
        # 修复：原来只捕获 AddressNotFoundError，非法IP字符串抛出的 ValueError 会漏出，
        # 导致整条 URL 的所有节点处理中断
        print(f"Error: {e}")
        return "Unknown"


# 处理sb，待办
def process_sb(data, index):
    try:
        json_data = json.loads(data)
        # 处理 shadowtls 数据

        # 提取所需字段
        method = json_data["outbounds"][0]["method"]
        password = json_data["outbounds"][0]["password"]
        server = json_data["outbounds"][1]["server"]
        server_port = json_data["outbounds"][1]["server_port"]
        server_name = json_data["outbounds"][1]["tls"]["server_name"]
        shadowtls_password = json_data["outbounds"][1]["password"]
        version = json_data["outbounds"][1]["version"]
        location = get_physical_location(server)
        name = f"{location}_shadowtls_{index}"
        # 创建当前网址的proxy字典
        proxy = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": server_port,
            "cipher": method,
            "password": password,
            "plugin": "shadow-tls",
            "client-fingerprint": "chrome",
            "plugin-opts": {
                "host": server_name,
                "password": shadowtls_password,
                "version": int(version),
            },
        }

        # 将当前proxy字典添加到所有proxies列表中
        merged_proxies.append(proxy)

    except Exception as e:
        logging.error(f"Error processing shadowtls data for index {index}: {e}")


def process_hysteria(data, index):
    try:
        json_data = json.loads(data)
        # 修复：auth 字段名在不同配置中为 auth_str / auth-str / auth，全部兼容
        auth = (
            json_data.get("auth_str")
            or json_data.get("auth-str")
            or json_data.get("auth")
            or ""
        )
        # 修复：server 拆分兼容 IPv6 和无端口
        server, server_port, mport = split_server_port(json_data.get("server", ""))
        # fast_open = json_data["fast_open"]
        fast_open = True
        insecure = json_data.get("insecure", False)
        server_name = json_data.get("server_name") or json_data.get("sni", "")
        alpn = json_data.get("alpn", "h3")
        protocol = json_data.get("protocol", "udp")
        location = get_physical_location(server)
        name = f"{location}_hy_{index}"

        # 创建当前网址的proxy字典
        proxy = {
            "name": name,
            "type": "hysteria",
            "server": server,
            "port": server_port,
            "ports": mport,
            "auth_str": auth,
            "up": 1000,
            "down": 1000,
            "fast-open": fast_open,
            "protocol": protocol,
            "sni": server_name,
            "skip-cert-verify": insecure,
            "alpn": [alpn] if isinstance(alpn, str) else alpn,
        }

        # 将当前proxy字典添加到所有proxies列表中
        merged_proxies.append(proxy)

    except Exception as e:
        logging.error(f"Error processing hysteria data for index {index}: {e}")


# 处理hysteria2
def process_hysteria2(data, index):
    try:
        json_data = json.loads(data)
        # 修复：auth 字段名兼容 auth / auth_str / password
        auth = (
            json_data.get("auth")
            or json_data.get("auth_str")
            or json_data.get("password")
            or ""
        )
        # 修复：server 拆分兼容 IPv6 和无端口
        server, server_port, _ = split_server_port(json_data.get("server", ""))
        # fast_open = json_data["fastOpen"]
        fast_open = True
        # 修复：tls 字段可能不存在
        tls_cfg = json_data.get("tls", {}) or {}
        insecure = tls_cfg.get("insecure", False)
        sni = tls_cfg.get("sni", "")
        location = get_physical_location(server)
        name = f"{location}_hy2_{index}"

        # 创建当前网址的proxy字典
        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": server_port,
            "password": auth,
            "fast-open": fast_open,
            "sni": sni,
            "skip-cert-verify": insecure,
        }

        # 将当前proxy字典添加到所有proxies列表中
        merged_proxies.append(proxy)

    except Exception as e:
        logging.error(f"Error processing hysteria2 data for index {index}: {e}")


# 处理xray
def process_xray(data, index):
    try:
        json_data = json.loads(data)
        # 处理 xray 数据
        outbound = json_data["outbounds"][0]
        protocol = outbound.get("protocol")
        # vless操作
        if protocol == "vless":
            vnext = outbound["settings"]["vnext"][0]
            server = vnext["address"]
            port = vnext["port"]
            user = vnext["users"][0]
            uuid = user.get("id", "")
            # 修复：flow 字段非 XTLS 节点没有，原来 user["flow"] 直接 KeyError
            flow = user.get("flow", "")

            stream = outbound.get("streamSettings", {})
            network = stream.get("network", "tcp")
            security = stream.get("security", "")

            # 修复：realitySettings 可能不存在（普通 tls 节点），
            # 原来直接取导致 KeyError，且 proxy 未赋值时仍执行 append 报 UnboundLocalError
            reality = stream.get("realitySettings", {}) or {}
            tls_settings = stream.get("tlsSettings", {}) or {}

            publicKey = reality.get("publicKey", "")
            shortId = reality.get("shortId", "")
            serverName = reality.get("serverName") or tls_settings.get(
                "serverName", ""
            )
            fingerprint = reality.get("fingerprint") or tls_settings.get(
                "fingerprint", "chrome"
            )
            istls = security in ("tls", "reality")
            isudp = True
            location = get_physical_location(server)
            tag = "reality" if security == "reality" else "vless"
            name = f"{location}_{tag}_{index}"

            proxy = {
                "name": name,
                "type": protocol,
                "server": server,
                "port": port,
                "uuid": uuid,
                "network": network,
                "tls": istls,
                "udp": isudp,
                "client-fingerprint": fingerprint,
                "servername": serverName,
            }
            if flow:
                proxy["flow"] = flow
            if security == "reality":
                proxy["reality-opts"] = {
                    "public-key": publicKey,
                    "short-id": shortId,
                }
            if network == "grpc":
                serviceName = stream.get("grpcSettings", {}).get("serviceName", "")
                proxy["grpc-opts"] = {"grpc-service-name": serviceName}
            elif network == "ws":
                ws_settings = stream.get("wsSettings", {}) or {}
                proxy["ws-opts"] = {
                    "path": ws_settings.get("path", "/"),
                    "headers": ws_settings.get("headers", {}),
                }

            # 修复：append 移入 if 内，protocol 非 vless 时不再触发 UnboundLocalError
            merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error processing xray data for index {index}: {e}")


def update_proxy_groups(config_data, merged_proxies):
    for group in config_data["proxy-groups"]:
        if group["name"] in ["自动选择", "节点选择"]:
            if "proxies" not in group or not group["proxies"]:
                group["proxies"] = [proxy["name"] for proxy in merged_proxies]
            else:
                group["proxies"].extend(proxy["name"] for proxy in merged_proxies)


def update_warp_proxy_groups(config_warp_data, merged_proxies):
    for group in config_warp_data["proxy-groups"]:
        if group["name"] in ["自动选择", "手动选择", "负载均衡"]:
            if "proxies" not in group or not group["proxies"]:
                group["proxies"] = [proxy["name"] for proxy in merged_proxies]
            else:
                group["proxies"].extend(proxy["name"] for proxy in merged_proxies)


# 包含hysteria2
merged_proxies = []

# 处理 clash URLs
process_urls("./urls/clash_urls.txt", process_clash)

# 处理 shadowtls URLs
# process_urls('./urls/sb_urls.txt', process_sb)

# 处理 hysteria URLs
process_urls("./urls/hysteria_urls.txt", process_hysteria)

# 处理 hysteria2 URLs
process_urls("./urls/hysteria2_urls.txt", process_hysteria2)

# 处理 xray URLs
process_urls("./urls/xray_urls.txt", process_xray)

# 读取普通的配置文件内容
with open("./templates/clash_template.yaml", "r", encoding="utf-8") as file:
    config_data = yaml.safe_load(file)

# 添加合并后的代理到proxies部分
if "proxies" not in config_data or not config_data["proxies"]:
    config_data["proxies"] = merged_proxies
else:
    config_data["proxies"].extend(merged_proxies)


# 更新自动选择和节点选择的proxies的name部分
update_proxy_groups(config_data, merged_proxies)

# 将更新后的数据写入到一个YAML文件中，并指定编码格式为UTF-8
with open("./sub/merged_proxies_new.yaml", "w", encoding="utf-8") as file:
    yaml.dump(config_data, file, sort_keys=False, allow_unicode=True)

print("聚合完成")
