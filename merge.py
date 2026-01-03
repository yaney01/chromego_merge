import base64
import json
import urllib.request
import yaml
import logging
import geoip2.database
import socket
import re

# 获取物理位置（国家名）
def get_physical_location(address):
    try:
        address = re.sub(":.*", "", address)
        ip_address = socket.gethostbyname(address)
    except Exception:
        return "Unknown"

    try:
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        response = reader.city(ip_address)
        return response.country.name or "Unknown"
    except Exception:
        return "Unknown"

# 通用处理 urls
def process_urls(url_file, processor):
    try:
        with open(url_file, "r") as file:
            urls = file.read().splitlines()
        for index, url in enumerate(urls):
            if not url:
                continue
            try:
                response = urllib.request.urlopen(url)
                data = response.read().decode("utf-8")
                processor(data, index)
            except Exception as e:
                logging.error(f"Error processing URL {url}: {e}")
    except Exception as e:
        logging.error(f"Error reading file {url_file}: {e}")

merged_proxies = []

### 处理 Clash 格式 ###
def process_clash(data, index):
    try:
        content = yaml.safe_load(data)
        if not isinstance(content, dict):
            return
        proxies = content.get("proxies", [])
        if not isinstance(proxies, list):
            return

        for proxy in proxies:
            insecure = int(proxy.get("skip-cert-verify", 0))

            t = proxy.get("type", "")
            server = proxy.get("server", "")
            port = proxy.get("port", "")
            location = get_physical_location(server)

            # vless
            if t == "vless":
                uuid = proxy.get("uuid", "")
                network = proxy.get("network", "")
                flow = proxy.get("flow", "")
                sni = proxy.get("servername", "")
                publicKey = proxy.get("reality-opts", {}).get("public-key", "")
                short_id = proxy.get("reality-opts", {}).get("short-id", "")
                ws_path = proxy.get("ws-opts", {}).get("path", "")
                ws_host = proxy.get("ws-opts", {}).get("headers", {}).get("Host", "")
                name = f"{location}_vless_{index}"
                security = "none" if proxy.get("tls", 0) == 0 else "tls"
                url = (
                    f"vless://{uuid}@{server}:{port}"
                    f"?security={security}&allowInsecure={insecure}"
                    f"&flow={flow}&type={network}&fp={proxy.get('client-fingerprint','')}"
                    f"&pbk={publicKey}&sid={short_id}&sni={sni}&path={ws_path}&host={ws_host}"
                    f"#{name}"
                )
                merged_proxies.append(url)

            # vmess
            if t == "vmess":
                uuid = proxy.get("uuid", "")
                network = proxy.get("network", "")
                sni = proxy.get("servername", "")
                ws_path = proxy.get("ws-opts", {}).get("path", "")
                ws_host = proxy.get("ws-opts", {}).get("headers", {}).get("Host", "")
                name = f"{location}_vmess_{index}"
                url = (
                    f"vmess://{uuid}@{server}:{port}"
                    f"?security=tls&allowInsecure={insecure}"
                    f"&type={network}&fp={proxy.get('client-fingerprint','')}"
                    f"&sni={sni}&path={ws_path}&host={ws_host}"
                    f"#{name}"
                )
                merged_proxies.append(url)

            # hysteria
            if t == "hysteria":
                auth = proxy.get("auth-str", "")
                upmbps = proxy.get("up_mbps", 50)
                downmbps = proxy.get("down_mbps", 80)
                protocol = proxy.get("protocol", "udp")
                sni = proxy.get("sni", "")
                alpn = proxy.get("alpn", [""])[0]
                name = f"{location}_hysteria_{index}"
                url = (
                    f"hysteria://{server}:{port}"
                    f"?peer={sni}&auth={auth}&insecure={insecure}"
                    f"&upmbps={upmbps}&downmbps={downmbps}&protocol={protocol}"
                    f"&alpn={alpn}#{name}"
                )
                merged_proxies.append(url)

            # ss / ssr / sstest
            if t == "ss":
                password = proxy.get("password", "")
                method = proxy.get("cipher", "")
                ss_source = f"{method}:{password}@{server}:{port}"
                ss_encode = base64.b64encode(ss_source.encode()).decode()
                merged_proxies.append(f"ss://{ss_encode}")

            if t == "ssr":
                password = base64.b64encode(proxy.get("password","").encode()).decode()
                proto = proxy.get("protocol","")
                cipher = proxy.get("cipher","")
                obfs = proxy.get("obfs","")
                obfs_param = base64.b64encode(proxy.get("obfs-param","").encode()).decode()
                proto_param = base64.b64encode(proxy.get("protocol-param","").encode()).decode()
                ssr_source = f"{server}:{port}:{proto}:{cipher}:{obfs}:{password}/?obfsparam={obfs_param}&protoparam={proto_param}"
                ssr_encode = base64.b64encode(ssr_source.encode()).decode()
                merged_proxies.append(f"ssr://{ssr_encode}")

    except Exception as e:
        logging.error(f"Error in process_clash: {e}")

### 处理 naiveproxy JSON ###
def process_naive(data, index):
    try:
        js = json.loads(data)
        proxy_str = js.get("proxy", "")
        if proxy_str:
            merged_proxies.append(base64.b64encode(proxy_str.encode()).decode())
    except Exception as e:
        logging.error(f"Error processing naive: {e}")

### 处理 hysteria2 JSON ###
def process_hysteria2(data, index):
    try:
        js = json.loads(data)
        server = js.get("server", "")
        tls = js.get("tls", {})
        insecure = int(tls.get("insecure", 0))
        sni = tls.get("sni","")
        auth = js.get("auth","")
        location = get_physical_location(server)
        name = f"{location}_hysteria2_{index}"
        url = f"hysteria2://{auth}@{server}?sni={sni}&allowInsecure={insecure}#{name}"
        merged_proxies.append(url)
    except Exception as e:
        logging.error(f"Error processing hysteria2: {e}")

### 处理 anytls (quick_urls) ###
def process_quick(data, index):
    try:
        content = yaml.safe_load(data)
        if not isinstance(content, dict):
            return
        proxies = content.get("proxies", [])
        for proxy in proxies:
            if proxy.get("type") != "anytls":
                continue
            server = proxy.get("server","")
            port = int(proxy.get("port",443))
            password = proxy.get("password","")
            fp = proxy.get("client-fingerprint","")
            udp = int(proxy.get("udp",False))
            insecure = int(proxy.get("skip-cert-verify",False))
            alpn = ",".join(proxy.get("alpn",[]))
            location = get_physical_location(server)
            name = f"{location}_anytls_{index}"
            url = (
                f"anytls://{password}@{server}:{port}"
                f"?fp={fp}&udp={udp}&alpn={alpn}&allowInsecure={insecure}#{name}"
            )
            merged_proxies.append(url)
    except Exception as e:
        logging.error(f"Error processing anytls: {e}")

### 主流程 ###
process_urls("./urls/clash_urls.txt", process_clash)
process_urls("./urls/naiverproxy_urls.txt", process_naive)
process_urls("./urls/hysteria2_urls.txt", process_hysteria2)
process_urls("./urls/quick_urls.txt", process_quick)

# 写出 base64 订阅
try:
    merged_content = "\n".join(merged_proxies)
    with open("./sub/base64.txt","w") as f:
        f.write(base64.b64encode(merged_content.encode()).decode())
    print("Written base64.txt")
except Exception as e:
    logging.error(f"Error writing base64: {e}")
