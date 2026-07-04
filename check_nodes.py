"""
TCP 连通性粗筛：仅对 base64 订阅做 TCP 握手，删除 IP 失效/端口关闭的死节点。
不经代理，结果与运行地区无关。hysteria/hysteria2/tuic 等 UDP 协议放行不测。
clash yaml 不处理，保持全量作为完整版。
"""

import base64
import concurrent.futures
import json
import os
import socket
import sys
import urllib.parse

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
BASE64_FILE = os.path.join(REPO_DIR, "sub", "base64.txt")
BASE64_BACKUP = os.path.join(REPO_DIR, "sub", "base64_full.txt")

TCP_TIMEOUT = 5
RETRIES = 2
CONCURRENCY = 32

UDP_SCHEMES = ("hysteria", "hysteria2", "hy2", "tuic", "wireguard", "wg")


def log(msg):
    print(msg, flush=True)


def tcp_alive(host, port):
    for _ in range(RETRIES):
        try:
            infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
            for family, socktype, proto, _, addr in infos:
                s = socket.socket(family, socktype, proto)
                s.settimeout(TCP_TIMEOUT)
                try:
                    s.connect(addr)
                    s.close()
                    return True
                except Exception:
                    s.close()
                    continue
        except Exception:
            continue
    return False


def extract_host_port(link):
    try:
        scheme = link.split("://", 1)[0].lower()

        if scheme == "vmess":
            raw = link[8:].split("#")[0]
            try:
                decoded = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8")
                v = json.loads(decoded)
                return (v["add"], int(v["port"]))
            except Exception:
                pass

        if scheme == "ss":
            body = link[5:].split("#")[0]
            if "@" not in body:
                try:
                    dec = base64.b64decode(body + "=" * (-len(body) % 4)).decode("utf-8")
                    hostport = dec.rsplit("@", 1)[1]
                    host, port = hostport.rsplit(":", 1)
                    return (host, int(port))
                except Exception:
                    return None

        if scheme == "ssr":
            try:
                raw = link[6:].split("#")[0].split("/")[0]
                dec = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8")
                parts = dec.split(":")
                return (parts[0], int(parts[1]))
            except Exception:
                return None

        u = urllib.parse.urlparse(link)
        if u.hostname and u.port:
            return (u.hostname, int(u.port))
        if u.hostname:
            return (u.hostname, 443)
    except Exception:
        return None
    return None


def test_link(link):
    scheme = link.split("://", 1)[0].lower()
    if scheme in UDP_SCHEMES:
        return (link, True)
    hp = extract_host_port(link)
    if hp is None:
        return (link, True)
    host, port = hp
    return (link, tcp_alive(host, port))


def main():
    if not os.path.exists(BASE64_FILE):
        log(f"{BASE64_FILE} 不存在")
        sys.exit(0)
    with open(BASE64_FILE, "r", encoding="utf-8") as f:
        b64 = f.read().strip()
    try:
        plain = base64.b64decode(b64).decode("utf-8")
    except Exception as e:
        log(f"base64 解码失败: {e}")
        sys.exit(0)
    links = [l.strip() for l in plain.splitlines() if l.strip()]
    total = len(links)
    if total == 0:
        log("无节点")
        sys.exit(0)

    log(f"开始 TCP 粗筛，共 {total} 个节点，并发 {CONCURRENCY}")
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futures = {ex.submit(test_link, l): l for l in links}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            link, ok = fut.result()
            done += 1
            if ok:
                alive.append(link)
            if done % 30 == 0:
                log(f"进度 {done}/{total}，存活 {len(alive)}")

    log(f"粗筛完成：删除 {total - len(alive)} 个死节点，保留 {len(alive)}/{total}")

    if len(alive) == 0:
        log("存活为0，保留原文件不覆盖")
        sys.exit(0)

    with open(BASE64_BACKUP, "w", encoding="utf-8") as f:
        f.write(b64)
    new_b64 = base64.b64encode("\n".join(alive).encode("utf-8")).decode("utf-8")
    with open(BASE64_FILE, "w", encoding="utf-8") as f:
        f.write(new_b64)
    log(f"已写回 {len(alive)} 个节点，备份至 base64_full.txt")


if __name__ == "__main__":
    main()
