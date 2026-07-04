"""
本地生成 sing-box 配置，不再依赖任何在线转换服务。
原理：克隆 Toperlock/sing-box-subscribe 到临时目录，读取本仓库刚生成的
./sub/base64.txt（同一次运行中 merge.py 的产物，比旧方案从 raw.githubusercontent
拉取"上一次运行的结果"更新鲜），解码为明文分享链接后本地转换。
"""

import base64
import json
import os
import subprocess
import sys
import tempfile

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
BASE64_FILE = os.path.join(REPO_DIR, "sub", "base64.txt")
OUTPUT_FILE = os.path.join(REPO_DIR, "sub", "sing-box.json")
CONVERTER_REPO = "https://github.com/Toperlock/sing-box-subscribe.git"
TEMPLATE_INDEX = "0"  # 0 = config_template_groups_rule_set_tun.json，与原在线服务默认模板一致


def fail(msg):
    # 保持与旧脚本一致的软失败：打印错误但退出码为0，
    # 避免 bash -e 中断后续 Commit 步骤导致 base64.txt 的更新一并丢失
    print(f"sing-box 配置生成失败: {msg}")
    sys.exit(0)


def main():
    # 1. 读取并解码本次运行刚生成的订阅
    if not os.path.exists(BASE64_FILE):
        fail(f"{BASE64_FILE} 不存在，请确认 merge.py 已先运行")
    with open(BASE64_FILE, "r", encoding="utf-8") as f:
        b64 = f.read().strip()
    try:
        plain = base64.b64decode(b64).decode("utf-8")
    except Exception as e:
        fail(f"base64.txt 解码失败: {e}")
    if not plain.strip():
        fail("订阅内容为空")

    workdir = tempfile.mkdtemp(prefix="sbsub_")
    converter_dir = os.path.join(workdir, "sing-box-subscribe")

    # 2. 克隆转换器
    r = subprocess.run(
        ["git", "clone", "-q", "--depth=1", CONVERTER_REPO, converter_dir],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        fail(f"克隆转换器失败: {r.stderr[:300]}")

    # 3. 安装转换器依赖（仓库主依赖 requirements.txt 已装过的会被 pip 跳过）
    req = os.path.join(converter_dir, "requirements.txt")
    r = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", "-r", req],
        capture_output=True, text=True,
    )
    if r.returncode != 0 and "externally-managed" in (r.stderr or ""):
        # 部分环境（PEP 668）需要该参数；GitHub Actions 的 setup-python 环境不需要
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q", "-r", req,
             "--break-system-packages"],
            capture_output=True, text=True,
        )
    if r.returncode != 0:
        fail(f"安装转换器依赖失败: {r.stderr[:300]}")

    # 4. 写明文分享链接文件 + providers.json（本地文件分支要求明文，不能给base64）
    plain_file = os.path.join(workdir, "plain_links.txt")
    with open(plain_file, "w", encoding="utf-8") as f:
        f.write(plain)

    providers = {
        "subscribes": [
            {
                "url": plain_file,
                "tag": "chromego",
                "enabled": True,
                "emoji": 0,
                "subgroup": "",
                "prefix": "",
                "User-Agent": "v2rayng",
            }
        ],
        "auto_set_outbounds_dns": {"proxy": "", "direct": ""},
        "save_config_path": OUTPUT_FILE,
        "auto_backup": False,
        "exclude_protocol": "ssr",
        "config_template": "",
        "Only-nodes": False,
    }
    with open(os.path.join(converter_dir, "providers.json"), "w", encoding="utf-8") as f:
        json.dump(providers, f, ensure_ascii=False, indent=2)

    # 5. 运行转换
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)  # 转换器对已存在文件会交互询问，先删除保证非交互
    r = subprocess.run(
        [sys.executable, "main.py", "--template_index", TEMPLATE_INDEX],
        cwd=converter_dir, capture_output=True, text=True, timeout=300,
    )
    if r.returncode != 0:
        fail(f"转换器运行失败: {(r.stderr or r.stdout)[:300]}")

    # 6. 校验输出
    if not os.path.exists(OUTPUT_FILE):
        fail(f"转换器未生成输出文件，日志: {r.stdout[-300:]}")
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
        node_types = {"vless", "vmess", "hysteria", "hysteria2", "tuic",
                      "shadowsocks", "trojan", "shadowsocksr", "wireguard"}
        nodes = [o for o in config.get("outbounds", [])
                 if o.get("type") in node_types]
    except Exception as e:
        fail(f"输出文件不是有效JSON: {e}")
    if not nodes:
        fail("输出配置中节点数为0，未写入")

    print(f"成功将内容写入 {OUTPUT_FILE}，节点数: {len(nodes)}")


if __name__ == "__main__":
    main()
