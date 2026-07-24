"""Generate sing-box output with a pinned local converter and atomic replacement."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from pipeline_common import MIN_NODES, PipelineError, ROOT

BASE64_FILE = ROOT / "sub" / "base64_full.txt"
OUTPUT_FILE = ROOT / "sub" / "sing-box.json"
CONVERTER_REPO = "https://github.com/Toperlock/sing-box-subscribe.git"
CONVERTER_COMMIT = "9b94f3e61d1a14e6eca228df189ada8719ca9174"
CONSTRAINTS_FILE = ROOT / "converter-constraints.txt"
TEMPLATE_INDEX = "0"
NODE_TYPES = {
    "anytls",
    "hysteria",
    "hysteria2",
    "http",
    "shadowsocks",
    "shadowsocksr",
    "socks",
    "trojan",
    "tuic",
    "vless",
    "vmess",
    "wireguard",
}


def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise PipelineError(f"命令失败 ({' '.join(command[:3])}): {detail[-1000:]}")
    return result


def existing_node_count() -> int:
    if not OUTPUT_FILE.exists():
        return 0
    try:
        config = json.loads(OUTPUT_FILE.read_text(encoding="utf-8"))
        return len(
            [
                outbound
                for outbound in config.get("outbounds", [])
                if isinstance(outbound, dict) and outbound.get("type") in NODE_TYPES
            ]
        )
    except Exception:
        return 0


def validate_output(path: Path, old_count: int) -> int:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PipelineError(f"转换结果不是有效 JSON: {exc}") from exc
    outbounds = config.get("outbounds") if isinstance(config, dict) else None
    if not isinstance(outbounds, list):
        raise PipelineError("转换结果缺少 outbounds")
    nodes = [
        outbound
        for outbound in outbounds
        if isinstance(outbound, dict) and outbound.get("type") in NODE_TYPES
    ]
    required = MIN_NODES if old_count == 0 else max(MIN_NODES, int(old_count * 0.5))
    if len(nodes) < required:
        raise PipelineError(
            f"sing-box 节点数异常: 新 {len(nodes)}，旧 {old_count}，最低要求 {required}"
        )
    return len(nodes)


def prepare_converter(directory: Path) -> Path:
    converter = directory / "sing-box-subscribe"
    run(["git", "init", "-q", str(converter)])
    run(["git", "-C", str(converter), "remote", "add", "origin", CONVERTER_REPO])
    run(
        [
            "git",
            "-C",
            str(converter),
            "fetch",
            "-q",
            "--depth=1",
            "origin",
            CONVERTER_COMMIT,
        ],
        timeout=120,
    )
    run(["git", "-C", str(converter), "checkout", "-q", "--detach", "FETCH_HEAD"])
    requirements = converter / "requirements.txt"
    run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "-q",
            "-r",
            str(requirements),
            "-c",
            str(CONSTRAINTS_FILE),
        ],
        timeout=300,
    )
    return converter


def main() -> None:
    if sys.version_info[:2] != (3, 11):
        raise PipelineError(f"需要 Python 3.11，当前为 {sys.version.split()[0]}")
    if not BASE64_FILE.exists():
        raise PipelineError(f"{BASE64_FILE} 不存在")
    if not CONSTRAINTS_FILE.exists():
        raise PipelineError(f"{CONSTRAINTS_FILE} 不存在")
    try:
        plain = base64.b64decode(
            BASE64_FILE.read_text(encoding="utf-8").strip(), validate=True
        ).decode("utf-8")
    except Exception as exc:
        raise PipelineError(f"base64.txt 解码失败: {exc}") from exc
    if not plain.strip():
        raise PipelineError("base64 订阅为空")

    old_count = existing_node_count()
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".sing-box.", suffix=".json", dir=OUTPUT_FILE.parent
    )
    os.close(descriptor)
    os.unlink(temporary_name)
    temporary_output = Path(temporary_name)

    try:
        with tempfile.TemporaryDirectory(prefix="sing-box-converter-") as work:
            workdir = Path(work)
            converter = prepare_converter(workdir)
            plain_file = workdir / "plain_links.txt"
            plain_file.write_text(plain, encoding="utf-8")
            providers = {
                "subscribes": [
                    {
                        "url": str(plain_file),
                        "tag": "chromego",
                        "enabled": True,
                        "emoji": 0,
                        "subgroup": "",
                        "prefix": "",
                        "User-Agent": "v2rayng",
                    }
                ],
                "auto_set_outbounds_dns": {"proxy": "", "direct": ""},
                "save_config_path": str(temporary_output),
                "auto_backup": False,
                "exclude_protocol": "ssr",
                "config_template": "",
                "Only-nodes": False,
            }
            (converter / "providers.json").write_text(
                json.dumps(providers, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            run(
                [sys.executable, "main.py", "--template_index", TEMPLATE_INDEX],
                cwd=converter,
                timeout=300,
            )
        if not temporary_output.exists():
            raise PipelineError("转换器没有生成输出文件")
        node_count = validate_output(temporary_output, old_count)
        os.replace(temporary_output, OUTPUT_FILE)
        print(f"sing-box 生成完成: {node_count} 个节点（旧 {old_count}）")
    finally:
        try:
            temporary_output.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"sing-box 配置生成失败: {exc}", file=sys.stderr)
        sys.exit(1)
