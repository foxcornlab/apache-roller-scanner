#!/usr/bin/env python3
"""Tests for roller_scanner.py — run with `python3 -m pytest tests/` or
`python3 -m unittest discover -s tests -v`. No network beyond localhost
mock servers, no real Roller needed."""

import json
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import roller_scanner as rs

ROLLER_HOME = """<html><head><title>My Blog</title>
<meta name="generator" content="Roller 6.1.4" />
</head><body><a href="/roller-ui/login.rol">login</a>
<p>Powered by Apache Roller</p></body></html>"""

ROLLER_HOME_FIXED = ROLLER_HOME.replace("Roller 6.1.4", "Roller 6.1.6")
ROLLER_HOME_NOVERSION = """<html><head><title>My Blog</title></head>
<body><a href="/roller-ui/login.rol">login</a>
<p>Powered by Apache Roller</p></body></html>"""
ROLLER_LOGIN = """<html><head><title>Roller: Login</title></head>
<body><h1>Apache Roller 6.1.4</h1></body></html>"""
NOT_ROLLER = """<html><head><title>Welcome to nginx!</title></head>
<body><h1>It works</h1></body></html>"""

XMLRPC_OK = """<?xml version="1.0"?><methodResponse><params><param>
<value><array><data><value><string>blogger.getUsersBlogs</string>
</value></data></array></value></param></params></methodResponse>"""


def make_handler(pages, xmlrpc_live=True):
    """Build a handler serving `pages` {path: body} and an XML-RPC endpoint."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            body = pages.get(self.path)
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            # The scanner must never send extension types.
            assert "ex:serializable" not in raw, "probe sent a serialized type"
            assert "serializable" not in raw, "probe sent a serialized type"
            if self.path == "/roller-services/xmlrpc" and xmlrpc_live:
                data = XMLRPC_OK.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/xml")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404)
                self.end_headers()

    return Handler


def serve(handler):
    """Start a mock server on localhost, return (server, base_url)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


class TestGrading(unittest.TestCase):
    def test_affected_range_is_vulnerable(self):
        for version in ("4.0.0", "5.0.0", "6.0.0", "6.1.4", "6.1.5"):
            verdict, _ = rs.grade(rs.parse_version(version)[0])
            self.assertEqual(verdict, "VULNERABLE", version)

    def test_fixed_from_616(self):
        for version in ("6.1.6", "6.1.7", "6.2.0"):
            verdict, _ = rs.grade(rs.parse_version(version)[0])
            self.assertEqual(verdict, "FIXED", version)

    def test_below_range_is_not_affected_by_this_cve(self):
        verdict, _ = rs.grade(rs.parse_version("3.5.0")[0])
        self.assertEqual(verdict, "NOT_AFFECTED")

    def test_garbage_is_unknown(self):
        verdict, _ = rs.grade(rs.parse_version("banana")[0])
        self.assertEqual(verdict, "UNKNOWN")

    def test_615_is_vulnerable_not_fixed(self):
        # The trap: some CVE aggregators list "fixed in 6.1.5" from the
        # CVE record's affected range. The Apache advisories say 6.1.5
        # is affected (CVE-2026-82384) and 6.1.6 is the first fix.
        verdict, _ = rs.grade(rs.parse_version("6.1.5")[0])
        self.assertEqual(verdict, "VULNERABLE")


class TestVersionExtraction(unittest.TestCase):
    def test_generator_meta(self):
        self.assertEqual(rs.extract_version(ROLLER_HOME), "6.1.4")

    def test_footer_text(self):
        self.assertEqual(rs.extract_version(ROLLER_LOGIN), "6.1.4")

    def test_no_version(self):
        self.assertIsNone(rs.extract_version(NOT_ROLLER))

    def test_fingerprint(self):
        self.assertTrue(rs.looks_like_roller(ROLLER_HOME))
        self.assertTrue(rs.looks_like_roller(ROLLER_LOGIN))
        self.assertFalse(rs.looks_like_roller(NOT_ROLLER))


class TestUrlProbe(unittest.TestCase):
    def test_vulnerable_roller_with_live_endpoint(self):
        server, base = serve(make_handler({
            "/": ROLLER_HOME,
            "/roller-ui/login.rol": ROLLER_LOGIN,
        }))
        try:
            result = rs.probe_url(base)
        finally:
            server.shutdown()
        self.assertTrue(result["is_roller"])
        self.assertEqual(result["version"], "6.1.4")
        self.assertTrue(result["endpoint_live"])
        self.assertEqual(result["verdict"], "VULNERABLE")

    def test_fixed_roller_with_live_endpoint(self):
        server, base = serve(make_handler({
            "/": ROLLER_HOME_FIXED,
            "/roller-ui/login.rol": ROLLER_LOGIN.replace("6.1.4", "6.1.6"),
        }))
        try:
            result = rs.probe_url(base)
        finally:
            server.shutdown()
        self.assertEqual(result["version"], "6.1.6")
        self.assertTrue(result["endpoint_live"])
        self.assertEqual(result["verdict"], "FIXED")
        self.assertIn("rejects requests", result["detail"])

    def test_not_roller(self):
        server, base = serve(make_handler({"/": NOT_ROLLER}))
        try:
            result = rs.probe_url(base)
        finally:
            server.shutdown()
        self.assertEqual(result["verdict"], "NOT_ROLLER")
        self.assertFalse(result["is_roller"])

    def test_roller_version_hidden_endpoint_live_is_unknown(self):
        server, base = serve(make_handler({
            "/": ROLLER_HOME_NOVERSION,
            "/roller-ui/login.rol": ROLLER_HOME_NOVERSION,
        }))
        try:
            result = rs.probe_url(base)
        finally:
            server.shutdown()
        self.assertTrue(result["is_roller"])
        self.assertIsNone(result["version"])
        self.assertTrue(result["endpoint_live"])
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertIn("treat as vulnerable", result["detail"])

    def test_vulnerable_version_endpoint_absent_still_vulnerable(self):
        server, base = serve(make_handler({
            "/": ROLLER_HOME,
            "/roller-ui/login.rol": ROLLER_LOGIN,
        }, xmlrpc_live=False))
        try:
            result = rs.probe_url(base)
        finally:
            server.shutdown()
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertFalse(result["endpoint_live"])

    def test_probe_never_sends_serialized_types(self):
        # Enforced by the assert inside the mock handler's do_POST.
        server, base = serve(make_handler({"/": ROLLER_HOME}))
        try:
            live, _ = rs.probe_xmlrpc(base)
        finally:
            server.shutdown()
        self.assertTrue(live)


class TestLocalMode(unittest.TestCase):
    WEBXML_VULN = """<?xml version="1.0"?><web-app>
<servlet><servlet-name>XmlRpcServlet</servlet-name>
<init-param><param-name>enabledForExtensions</param-name>
<param-value>true</param-value></init-param></servlet>
<servlet-mapping><servlet-name>XmlRpcServlet</servlet-name>
<url-pattern>/roller-services/xmlrpc</url-pattern></servlet-mapping>
</web-app>"""
    WEBXML_MITIGATED = WEBXML_VULN.replace(
        "<param-value>true</param-value>", "<param-value>false</param-value>"
    )
    MANIFEST = "Manifest-Version: 1.0\nImplementation-Version: 6.1.4\n"

    def _install(self, root, webxml, manifest=True):
        webinf = Path(root) / "WEB-INF"
        webinf.mkdir(parents=True)
        (webinf / "web.xml").write_text(webxml)
        if manifest:
            meta = Path(root) / "META-INF"
            meta.mkdir()
            (meta / "MANIFEST.MF").write_text(self.MANIFEST)

    def test_local_vulnerable_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._install(tmp, self.WEBXML_VULN)
            result = rs.read_local(tmp)
        self.assertEqual(result["version"], "6.1.4")
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertEqual(result["webxml"]["enabledForExtensions"], "true")
        self.assertTrue(result["webxml"]["xmlrpc_mapping_present"])

    def test_local_mitigated_webxml_noted(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._install(tmp, self.WEBXML_MITIGATED)
            result = rs.read_local(tmp)
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertIn("already false in web.xml", result["detail"])

    def test_local_fixed_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._install(tmp, self.WEBXML_VULN)
            manifest = Path(tmp) / "META-INF" / "MANIFEST.MF"
            manifest.write_text(
                "Manifest-Version: 1.0\nImplementation-Version: 6.1.6\n"
            )
            result = rs.read_local(tmp)
        self.assertEqual(result["verdict"], "FIXED")

    def test_local_war_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            war = Path(tmp) / "roller.war"
            with zipfile.ZipFile(war, "w") as archive:
                archive.writestr("WEB-INF/web.xml", self.WEBXML_VULN)
                archive.writestr("META-INF/MANIFEST.MF", self.MANIFEST)
            result = rs.read_local(str(war))
        self.assertEqual(result["version"], "6.1.4")
        self.assertEqual(result["verdict"], "VULNERABLE")

    def test_local_not_an_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = rs.read_local(tmp)
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertIn("no WEB-INF", result["detail"])


class TestCli(unittest.TestCase):
    def test_version_mode_exits(self):
        self.assertEqual(rs.main(["--version", "6.1.4"]), 1)
        self.assertEqual(rs.main(["--version", "6.1.6"]), 0)
        self.assertEqual(rs.main(["--version", "banana"]), 2)

    def test_list_mode(self):
        self.assertEqual(rs.main(["--list"]), 0)

    def test_inventory_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            fleet = Path(tmp) / "fleet.json"
            fleet.write_text(json.dumps([
                {"host": "blog-a", "version": "6.1.4"},
                {"host": "blog-b", "version": "6.1.6"},
                {"host": "blog-c", "version": "5.2.0"},
            ]))
            self.assertEqual(rs.main(["--inventory-json", str(fleet)]), 1)


if __name__ == "__main__":
    unittest.main()
