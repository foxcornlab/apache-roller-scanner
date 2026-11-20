# `apache-roller-scanner`

Detection-only triage for `CVE-2026-129448`, the unauthenticated deserialization RCE in `Apache Roller` that Apache confirmed is being actively exploited (`2026-11-17`). Grades your `Roller` version against the fixed release, fingerprints a live install, and probes the `XML-RPC` endpoint the way a defender would (one plain `system.listMethods` call, no parameters, no extension types). Nothing here sends a serialized object, so nothing here can trigger the flaw.

## `What it checks`

* `CVE-2026-129448` — deserialization of untrusted data in the `XML-RPC` endpoint. The endpoint accepts vendor extension types (`ex:serializable`) and deserializes them while parsing the request body, before Roller checks credentials or whether `XML-RPC` is even enabled. `CVSS 3.1 9.8` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), `CWE-502`. Affects `4.0.0` through `6.1.4`. Apache: "This issue is being actively exploited."
* `CVE-2026-82384` — the same flaw, disclosed `September 2026`, listed only `6.1.5` as affected. The `November` advisory corrects the range: the bug was in every release from `4.0.0` up, `6.1.5` included. Both CVEs are `CVSS 9.8`. One fix covers both: upgrade to `6.1.6` or later.

Fixed versions, per the Apache security advisories (primary source):

| `Build` | `Upgrade to` |
| --- | --- |
| `Apache Roller 4.0.0` through `6.1.5` | `6.1.6` or later |
| `Apache Roller 6.1.6` and up | already fixed (`6.1.7` is the newest release seen) |

`6.1.6` disables the extension types outright and rejects `XML-RPC` requests when the feature is disabled. A public proof of concept has been on `GitHub` since `28 September 2026`; this scanner is the defensive counterpart to it, it sends no payloads. Not in CISA KEV as of `2026-11-19`, but Apache's own exploitation confirmation is the reason to move now, not a KEV entry.

## `Usage`

```bash
# grade a version string
python3 roller_scanner.py --version "6.1.4"
python3 roller_scanner.py --version "6.1.6"

# a live server: fingerprint + one benign XML-RPC call, no payloads
python3 roller_scanner.py --url https://roller.example.com
python3 roller_scanner.py --url http://192.0.2.10:8080/roller

# on the Roller box itself (version + web.xml mitigations)
python3 roller_scanner.py --local /opt/roller
python3 roller_scanner.py --local /tmp/roller.war

# a whole fleet at once
python3 roller_scanner.py --inventory-json fleet.json

# machine output / the fixed-version table
python3 roller_scanner.py --version "6.1.4" --json
python3 roller_scanner.py --list
```

`--url` fetches the homepage and the login page (`/roller-ui/login.rol`), reads the version out of the HTML, then `POST`s one plain `system.listMethods` call to `/roller-services/xmlrpc` and checks whether the endpoint answers with an `XML-RPC` response. `--local` reads the version from `META-INF/MANIFEST.MF` (or a version properties file) and reads `WEB-INF/web.xml` for the two real mitigations: `enabledForExtensions` and the `xmlrpc` servlet mapping. `--inventory-json` takes a list of `{"host": "blog-1", "version": "6.1.4"}` or `{"host": "blog-1", "url": "https://..."}` objects.

Exit codes: `0` patched / not affected / not Roller, `1` vulnerable, `2` unknown, `3` usage error.

## `Traps`

* The `6.1.5` trap. Some CVE aggregators list "fixed in `6.1.5`" because the CVE record's affected range reads `>=4.0.0 <6.1.5`. Apache's own advisories say the opposite: `CVE-2026-82384` lists `6.1.5` as affected and recommends `6.1.6` or later, and the `6.1.6` release announcement tells users of `6.1.5` and earlier to upgrade. This scanner follows the vendor. `6.1.5` grades `VULNERABLE`.
* The admin-UI trap. Turning `XML-RPC` off in the Roller admin UI does **not** protect releases below `6.1.6`. The vulnerable code deserializes the request before it ever consults that setting, so the switch is checked too late. If you cannot upgrade today, set `enabledForExtensions` to `false` in `WEB-INF/web.xml`, or remove the `/roller-services/xmlrpc` servlet mapping, and restart. `--local` checks both for you.
* The version-hidden trap. Roller does not always print its version on the homepage. If the install is confirmed Roller and the endpoint is live but no version is exposed, this scanner grades `UNKNOWN` and says treat it as vulnerable until the version is checked on the box. A hidden version is not a patched version.
* The `6.1.6` upgrade trap. Check the `6.1.6` release notes before upgrading: `WSSE AtomPub` authentication is retired and installs still configured for it fail at startup, initial setup and database migrations need a one-time token printed to the server log, and Trackback support is removed. The upgrade is still the fix, just do it with the notes open.
* The endpoint-quiet trap. A vulnerable version grades `VULNERABLE` even when the endpoint probe gets no answer. The servlet is mapped unconditionally on affected releases, so a silent probe (a `WAF` in front, a reverse proxy rule) does not mean the flaw is gone.

## `Sources`

* Apache Roller security advisories, `CVE-2026-129448` and `CVE-2026-82384` (`lists.apache.org`, primary source for the affected range and the `6.1.6` fix)
* `BleepingComputer`, `The Hacker News`, `Security Affairs` (`2026-11-18`, exploitation confirmation)
* `Corgea` research note on `CVE-2026-129448` / `CVE-2026-82384` (public PoC date, `6.1.7` release)
* `OffSeq Threat Radar` and `cve-security.com` (no public `nuclei` template or remote detection signal indexed as of `2026-11-19`, which is why this scanner exists)

Where sources disagree, this scanner follows the vendor advisory and says so. The one live disagreement is the fixed version: aggregator CVE data says `6.1.5`, Apache says `6.1.6`. Apache wins.

## `Thanks to`

* `n0mi1k` — found the flaw
* `Matt Raible` — reported it
* The `Apache Roller` team — for the advisory and the `6.1.6` fix

Educational and defensive use only. This tool detects exposure, it does not exploit anything. If you run a Roller install, patch it.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
