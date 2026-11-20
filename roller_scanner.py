#!/usr/bin/env python3
"""Detection-only triage for Apache Roller CVE-2026-129448 (and CVE-2026-82384).

Unauthenticated remote code execution through deserialization of
untrusted data in the XML-RPC endpoint. The endpoint accepts vendor
extension types (``ex:serializable``) and deserializes them while
parsing the request body, before Roller checks credentials or whether
XML-RPC is even enabled. CVSS 3.1 9.8
(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H), CWE-502. Apache
confirmed active exploitation on 2026-11-17.

Detection only. This scanner never sends a serialized object, an
extension type, or any exploit traffic. The only XML-RPC call it makes
is a plain ``system.listMethods`` with no parameters, which cannot
trigger deserialization. Everything else is version-table grading and
reading HTML your server already serves to anyone.

Fixed release: 6.1.6 or later, per the Apache advisories (primary
source). Affected: 4.0.0 through 6.1.5. CVE-2026-82384 (September
2026) listed only 6.1.5 as affected; CVE-2026-129448 (17 November
2026) is the same flaw with the range corrected to 4.0.0 through
6.1.4, and states it is being actively exploited.
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

VERSION = "1.0.0"

CVE_MAIN = "CVE-2026-129448"
CVE_EARLIER = "CVE-2026-82384"
CVSS = "9.8"
CWE = "CWE-502"

# First release with the fix, per the Apache security advisories.
FIXED = (6, 1, 6)
# Advisory scope starts here; older releases are outside this CVE's
# stated range (they carry their own old flaws, this is not a clean bill).
AFFECTED_FROM = (4, 0, 0)

XMLRPC_PATH = "/roller-services/xmlrpc"
LOGIN_PATH = "/roller-ui/login.rol"

EXIT_CLEAN = 0
EXIT_VULNERABLE = 1
EXIT_UNKNOWN = 2
EXIT_USAGE = 3

ROLLER_MARKERS = (
    "apache roller",
    "roller-ui",
    "/roller-services/",
    "powered by roller",
    "metaweblog",
)

VERSION_PATTERNS = (
    re.compile(r"Roller\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    re.compile(r"roller[/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    re.compile(r"generator[^>]*Roller\s+([\d.]+)", re.IGNORECASE),
    re.compile(r"Apache Roller\s+([\d.]+)", re.IGNORECASE),
)

# A plain method call with no parameters and no extension types. This
# cannot trigger deserialization; a live endpoint answers with a
# <methodResponse> (a result, or a fault for an unknown method).
BENIGN_XMLRPC_CALL = (
    '<?xml version="1.0"?>'
    "<methodCall><methodName>system.listMethods</methodName>"
    "<params></params></methodCall>"
)


def ver_tuple(text):
    """Parse "6.1.4" into (6, 1, 4). Returns None if unparseable."""
    parts = text.strip().split(".")
    if not 2 <= len(parts) <= 4:
        return None
    try:
        nums = tuple(int(p) for p in parts)
    except ValueError:
        return None
    return nums


def cmp_ver(a, b):
    """Compare two version tuples of possibly different lengths."""
    n = max(len(a), len(b))
    aa = a + (0,) * (n - len(a))
    bb = b + (0,) * (n - len(b))
    return (aa > bb) - (aa < bb)


def parse_version(raw):
    """Split a version string into (tuple, suffix_flag).

    suffix_flag is True when the string carries a build suffix such as
    "6.1.5-1". Roller ships as a WAR from Apache, so a suffix is unusual;
    the number is still graded, with the suffix noted.
    """
    s = raw.strip()
    s = re.sub(r"^roller[/\s-]+", "", s, flags=re.IGNORECASE)
    s = re.sub(r"^v", "", s)
    token = s.split()[0] if s.split() else ""
    if "-" in token:
        base, _suffix = token.split("-", 1)
        return ver_tuple(base), True
    return ver_tuple(token), False


def grade(version):
    """Grade a parsed version tuple.

    Returns (verdict, detail) where verdict is one of VULNERABLE,
    FIXED, NOT_AFFECTED, UNKNOWN.
    """
    if version is None:
        return "UNKNOWN", "no parseable version"
    if cmp_ver(version, AFFECTED_FROM) < 0:
        return "NOT_AFFECTED", (
            "below the advisory range (4.0.0+); this CVE does not cover "
            "it, which is not a clean bill for a release this old"
        )
    if cmp_ver(version, FIXED) < 0:
        return "VULNERABLE", (
            "in the affected range 4.0.0 through 6.1.5; upgrade to "
            "6.1.6 or later"
        )
    return "FIXED", "6.1.6 or later carries the fix"


def extract_version(text):
    """Pull a Roller version number out of page HTML. None if absent."""
    if not text:
        return None
    for pattern in VERSION_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def looks_like_roller(text):
    """True when page text carries Roller fingerprints."""
    if not text:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in ROLLER_MARKERS)


def fetch(url, data=None, timeout=10):
    """GET (or POST when data is given). Returns (status, headers, text).

    Status None means the connection itself failed; the detail string
    says why.
    """
    headers = {"User-Agent": "roller-scanner/1.0 (detection-only triage)"}
    if data is not None:
        headers["Content-Type"] = "text/xml"
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, dict(resp.headers), body, None
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, dict(exc.headers or {}), body, None
    except Exception as exc:  # connection refused, DNS, timeout, TLS
        return None, {}, "", str(exc)


def probe_xmlrpc(base):
    """Check whether the XML-RPC endpoint answers a benign call.

    Returns (live, detail). live is True only when the endpoint
    returns an XML-RPC <methodResponse>. A 404 or a non-XML answer
    means the endpoint is not exposed at that path.
    """
    url = base.rstrip("/") + XMLRPC_PATH
    status, _headers, body, error = fetch(
        url, data=BENIGN_XMLRPC_CALL.encode("utf-8")
    )
    if status is None:
        return False, "endpoint unreachable (%s)" % error
    if "<methodResponse>" in body:
        return True, "endpoint answered a plain system.listMethods call"
    if status == 404:
        return False, "endpoint returned 404 (not mapped)"
    return False, "endpoint returned HTTP %s without an XML-RPC response" % status


def probe_url(base):
    """Fingerprint a live Roller install and grade it.

    Returns a result dict. Never sends anything but plain GETs and one
    benign XML-RPC call with no extension types.
    """
    result = {
        "target": base,
        "is_roller": False,
        "version": None,
        "version_source": None,
        "endpoint_live": None,
        "endpoint_detail": None,
        "verdict": "UNKNOWN",
        "detail": "",
    }

    pages = []
    for path in ("", LOGIN_PATH):
        status, _headers, body, _error = fetch(base.rstrip("/") + path)
        if status is not None and body:
            pages.append((path or "/", body))

    if not any(looks_like_roller(body) for _path, body in pages):
        result["verdict"] = "NOT_ROLLER"
        result["detail"] = "no Roller fingerprints on the homepage or login page"
        return result
    result["is_roller"] = True

    for path, body in pages:
        found = extract_version(body)
        if found:
            result["version"] = found
            result["version_source"] = path
            break

    live, detail = probe_xmlrpc(base)
    result["endpoint_live"] = live
    result["endpoint_detail"] = detail

    if result["version"] is not None:
        parsed, _suffix = parse_version(result["version"])
        verdict, why = grade(parsed)
        result["verdict"] = verdict
        result["detail"] = why
        if verdict == "FIXED" and live:
            result["detail"] += (
                "; the XML-RPC endpoint still answers, which is expected "
                "on 6.1.6+ (it now rejects requests when the feature is "
                "off) — confirm XML-RPC is disabled if you do not use it"
            )
        if verdict == "VULNERABLE" and not live:
            result["detail"] += (
                "; the endpoint did not answer this probe, but the "
                "version alone is enough to call it vulnerable — the "
                "servlet is mapped unconditionally on affected releases"
            )
        return result

    # Roller confirmed, version unknown: the endpoint state decides
    # how urgent the unknown is.
    if live:
        result["verdict"] = "UNKNOWN"
        result["detail"] = (
            "Roller confirmed and the XML-RPC endpoint is live, but no "
            "version number was exposed — treat as vulnerable until the "
            "version is checked on the box"
        )
    else:
        result["verdict"] = "UNKNOWN"
        result["detail"] = (
            "Roller confirmed but no version number was exposed and the "
            "endpoint did not answer — check the version on the box"
        )
    return result


def read_local(path):
    """Grade a Roller install on disk (directory or .war file).

    Also reads WEB-INF/web.xml for the two real mitigations: the
    enabledForExtensions setting and whether the xmlrpc servlet
    mapping is still present. Returns a result dict.
    """
    result = {
        "target": str(path),
        "is_roller": False,
        "version": None,
        "version_source": None,
        "endpoint_live": None,
        "endpoint_detail": None,
        "verdict": "UNKNOWN",
        "detail": "",
        "webxml": {},
    }
    target = Path(path)
    files = {}

    if target.is_dir():
        webinf = target / "WEB-INF"
        if not webinf.is_dir():
            result["detail"] = "not a Roller install: no WEB-INF directory"
            return result
        for item in target.rglob("*"):
            if item.is_file():
                try:
                    files[str(item.relative_to(target))] = item.read_bytes()
                except OSError:
                    continue
    elif target.is_file() and zipfile.is_zipfile(target):
        with zipfile.ZipFile(target) as war:
            for name in war.namelist():
                if name.endswith("/"):
                    continue
                try:
                    files[name] = war.read(name)
                except KeyError:
                    continue
    else:
        result["detail"] = "path is neither a directory nor a .war file"
        return result

    # Version: MANIFEST first, then any version properties file.
    for name, content in files.items():
        if name.endswith("META-INF/MANIFEST.MF"):
            text = content.decode("utf-8", errors="replace")
            match = re.search(
                r"Implementation-Version:\s*([\d.]+)", text
            )
            if match:
                result["version"] = match.group(1)
                result["version_source"] = name
                break
    if result["version"] is None:
        for name, content in files.items():
            if "version" in name.lower() and name.endswith(".properties"):
                text = content.decode("utf-8", errors="replace")
                match = re.search(r"version\s*=\s*([\d.]+)", text)
                if match:
                    result["version"] = match.group(1)
                    result["version_source"] = name
                    break

    webxml_text = None
    for name, content in files.items():
        if name.endswith("WEB-INF/web.xml"):
            webxml_text = content.decode("utf-8", errors="replace")
            break

    if webxml_text is not None:
        result["is_roller"] = True
        ext = re.search(
            r"enabledForExtensions</param-name>\s*"
            r"<param-value>\s*(true|false)\s*</param-value>",
            webxml_text,
            re.IGNORECASE,
        )
        mapping = re.search(
            r"<url-pattern>\s*/roller-services/xmlrpc\s*</url-pattern>",
            webxml_text,
        )
        result["webxml"] = {
            "enabledForExtensions": ext.group(1).lower() if ext else None,
            "xmlrpc_mapping_present": bool(mapping),
        }

    if not result["is_roller"] and result["version"] is None:
        result["detail"] = (
            "no WEB-INF/web.xml and no version found — not a Roller "
            "install as far as this scan can tell"
        )
        return result
    result["is_roller"] = True

    parsed, _suffix = parse_version(result["version"]) if result["version"] else (None, False)
    verdict, why = grade(parsed)
    result["verdict"] = verdict
    result["detail"] = why

    webxml = result["webxml"]
    if verdict == "VULNERABLE" and webxml:
        if webxml.get("enabledForExtensions") == "false":
            result["detail"] += (
                "; enabledForExtensions is already false in web.xml, "
                "which is the real mitigation — still upgrade, the "
                "setting is the only thing standing between you and it"
            )
        elif webxml.get("xmlrpc_mapping_present") is False:
            result["detail"] += (
                "; the /roller-services/xmlrpc servlet mapping has been "
                "removed from web.xml, which blocks the endpoint — "
                "still upgrade, the mapping is the only thing standing "
                "between you and it"
            )
        else:
            result["detail"] += (
                "; enabledForExtensions is still true (or unset, which "
                "defaults to the vulnerable behaviour) and the servlet "
                "mapping is present — set it false in WEB-INF/web.xml "
                "or remove the mapping, then restart, if you cannot "
                "upgrade today"
            )
    return result


def verdict_exit(verdict):
    """Map a verdict to this tool's exit code."""
    if verdict == "VULNERABLE":
        return EXIT_VULNERABLE
    if verdict in ("UNKNOWN",):
        return EXIT_UNKNOWN
    return EXIT_CLEAN


def summarise(results):
    """One-line human summary plus the worst exit code."""
    counts = {}
    for item in results:
        counts[item["verdict"]] = counts.get(item["verdict"], 0) + 1
    worst = EXIT_CLEAN
    for item in results:
        worst = max(worst, verdict_exit(item["verdict"]))
    parts = ["%s: %d" % (key, counts[key]) for key in sorted(counts)]
    return ", ".join(parts), worst


def print_result(result, as_json=False):
    """Render one result for a human, or as JSON."""
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print("target: %s" % result["target"])
    if result.get("version"):
        source = result.get("version_source") or "given"
        print("version: %s (from %s)" % (result["version"], source))
    if result.get("endpoint_live") is not None:
        print("xmlrpc endpoint live: %s — %s" % (result["endpoint_live"], result["endpoint_detail"]))
    if result.get("webxml"):
        print("web.xml: %s" % json.dumps(result["webxml"]))
    print("verdict: %s" % result["verdict"])
    print(result["detail"])


def main(argv=None):
    """Parse args, run one mode, exit 0/1/2/3."""
    parser = argparse.ArgumentParser(
        description="Detection-only triage for Apache Roller %s / %s "
        "(unauthenticated XML-RPC deserialization RCE, CVSS 9.8). "
        "No payloads, no exploit traffic." % (CVE_MAIN, CVE_EARLIER)
    )
    parser.add_argument("--version", metavar="VERSION",
                        help='grade a version string, e.g. "6.1.4"')
    parser.add_argument("--url", metavar="URL",
                        help="probe a live Roller install, e.g. https://roller.example.com")
    parser.add_argument("--local", metavar="PATH",
                        help="grade a Roller install on disk (directory or .war file)")
    parser.add_argument("--inventory-json", metavar="FILE",
                        help="grade a fleet: JSON list of {\"host\", \"version\"} "
                        "and/or {\"host\", \"url\"} objects")
    parser.add_argument("--list", action="store_true",
                        help="print the fixed-version table and exit")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    args = parser.parse_args(argv)

    if args.list:
        table = {
            "cve": [CVE_MAIN, CVE_EARLIER],
            "cvss": CVSS,
            "cwe": CWE,
            "affected": "4.0.0 through 6.1.5",
            "fixed": "6.1.6 or later (6.1.7 is the newest release seen)",
            "endpoint": XMLRPC_PATH,
            "exploited": "yes, confirmed by Apache 2026-11-17",
            "cisa_kev": "not listed as of 2026-11-19",
        }
        if args.json:
            print(json.dumps(table, indent=2, sort_keys=True))
        else:
            for key, value in table.items():
                print("%s: %s" % (key, value))
        return EXIT_CLEAN

    modes = [args.version, args.url, args.local, args.inventory_json]
    if sum(1 for mode in modes if mode) != 1:
        parser.error("exactly one of --version, --url, --local, --inventory-json is required")

    if args.version:
        parsed, suffix = parse_version(args.version)
        verdict, detail = grade(parsed)
        result = {
            "target": args.version,
            "version": args.version,
            "verdict": verdict,
            "detail": detail,
        }
        print_result(result, as_json=args.json)
        return verdict_exit(verdict)

    if args.url:
        result = probe_url(args.url)
        print_result(result, as_json=args.json)
        return verdict_exit(result["verdict"])

    if args.local:
        result = read_local(args.local)
        print_result(result, as_json=args.json)
        return verdict_exit(result["verdict"])

    # --inventory-json
    try:
        inventory = json.loads(Path(args.inventory_json).read_text())
    except (OSError, ValueError) as exc:
        print("cannot read inventory: %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    if not isinstance(inventory, list):
        print("inventory must be a JSON list", file=sys.stderr)
        return EXIT_USAGE

    results = []
    for entry in inventory:
        host = entry.get("host", "?")
        if entry.get("version"):
            parsed, _suffix = parse_version(entry["version"])
            verdict, detail = grade(parsed)
            results.append({
                "target": host,
                "version": entry["version"],
                "verdict": verdict,
                "detail": detail,
            })
        elif entry.get("url"):
            result = probe_url(entry["url"])
            result["target"] = host
            results.append(result)
        else:
            results.append({
                "target": host,
                "verdict": "UNKNOWN",
                "detail": "entry has neither version nor url",
            })

    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
    else:
        for result in results:
            print_result(result)
            print("---")
        summary, _worst = summarise(results)
        print("summary: %s" % summary)
    _summary, worst = summarise(results)
    return worst


if __name__ == "__main__":
    sys.exit(main())
