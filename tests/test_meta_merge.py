import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from meta_merge import parse_singbox
from pipeline_common import PipelineError, collect_sources


class SingBoxHysteriaTests(unittest.TestCase):
    def test_converts_hysteria_outbound(self) -> None:
        config = {
            "outbounds": [
                {
                    "type": "hysteria",
                    "tag": "hy1",
                    "server": "example.com",
                    "server_port": 443,
                    "server_ports": ["1000", "2000-3000"],
                    "auth_str": "secret",
                    "up_mbps": 20,
                    "down_mbps": 50,
                    "obfs": "mask",
                    "tls": {
                        "enabled": True,
                        "server_name": "sni.example.com",
                        "insecure": True,
                        "alpn": ["h3"],
                    },
                }
            ]
        }

        [node] = parse_singbox(json.dumps(config), "sb_urls:1")

        self.assertEqual(
            node,
            {
                "name": "hy1",
                "type": "hysteria",
                "server": "example.com",
                "port": 443,
                "ports": "1000,2000-3000",
                "auth-str": "secret",
                "protocol": "udp",
                "up": 20,
                "down": 50,
                "sni": "sni.example.com",
                "skip-cert-verify": True,
                "fast-open": False,
                "obfs": "mask",
                "alpn": ["h3"],
            },
        )

    def test_accepts_hyphenated_auth_str(self) -> None:
        config = {
            "outbounds": [
                {
                    "type": "hysteria",
                    "server": "example.com",
                    "server_port": 8443,
                    "auth-str": "secret",
                }
            ]
        }

        [node] = parse_singbox(json.dumps(config), "sb_urls:2")

        self.assertEqual(node["auth-str"], "secret")
        self.assertEqual(node["port"], 8443)

    def test_converts_hysteria2_outbound(self) -> None:
        config = {
            "outbounds": [
                {
                    "type": "hysteria2",
                    "tag": "hy2",
                    "server": "example.com",
                    "server_port": 443,
                    "server_ports": ["2000:3000", 4000],
                    "password": "secret",
                    "up_mbps": 20,
                    "down_mbps": 50,
                    "obfs": {"type": "salamander", "password": "mask"},
                    "tls": {
                        "enabled": True,
                        "server_name": "sni.example.com",
                        "insecure": True,
                        "alpn": ["h3"],
                    },
                }
            ]
        }

        [node] = parse_singbox(json.dumps(config), "sb_urls:3")

        self.assertEqual(
            node,
            {
                "name": "hy2",
                "type": "hysteria2",
                "server": "example.com",
                "port": 443,
                "ports": "2000-3000,4000",
                "password": "secret",
                "up": 20,
                "down": 50,
                "obfs": "salamander",
                "obfs-password": "mask",
                "sni": "sni.example.com",
                "skip-cert-verify": True,
                "alpn": ["h3"],
            },
        )

    def test_hysteria2_accepts_auth_variants_without_bandwidth(self) -> None:
        for auth_key in ("auth", "auth_str"):
            with self.subTest(auth_key=auth_key):
                config = {
                    "outbounds": [
                        {
                            "type": "hysteria2",
                            "server": "example.com",
                            "server_ports": "8443:9443",
                            auth_key: "secret",
                            "tls": {"server_name": "sni.example.com"},
                        }
                    ]
                }

                [node] = parse_singbox(json.dumps(config), "sb_urls:4")

                self.assertEqual(node["port"], 8443)
                self.assertEqual(node["ports"], "8443-9443")
                self.assertEqual(node["password"], "secret")
                self.assertNotIn("up", node)
                self.assertNotIn("down", node)


class CollectSourcesTests(unittest.TestCase):
    @patch("pipeline_common.read_url_list", return_value=["bad", "good"])
    @patch("pipeline_common.fetch_text", side_effect=["bad", "good"])
    def test_skips_failed_source_when_another_source_succeeds(
        self, _fetch_text, _read_url_list
    ) -> None:
        def parser(data: str, source: str) -> list[dict[str, str]]:
            if data == "bad":
                raise PipelineError("invalid")
            return [{"name": source}]

        output = io.StringIO()
        with redirect_stdout(output):
            nodes = collect_sources("urls/example.txt", parser)

        self.assertEqual(nodes, [{"name": "example:2"}])
        self.assertIn("警告", output.getvalue())
        self.assertIn("example:1", output.getvalue())

    @patch("pipeline_common.read_url_list", return_value=["bad"])
    @patch("pipeline_common.fetch_text", return_value="bad")
    def test_fails_when_all_sources_fail(self, _fetch_text, _read_url_list) -> None:
        def parser(_data: str, _source: str) -> list[dict[str, str]]:
            raise PipelineError("invalid")

        with self.assertRaisesRegex(PipelineError, "所有来源均失败"):
            collect_sources("urls/example.txt", parser)


if __name__ == "__main__":
    unittest.main()
