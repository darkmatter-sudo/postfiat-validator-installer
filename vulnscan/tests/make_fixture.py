#!/usr/bin/env python3
"""Build a small USN OVAL feed in the exact shape of Canonical's jammy feed (and, for the stubbed-oscap tests, the
matching `oscap oval eval --results` file).

  make_fixture.py feed OUT.xml [--ts ISO] [--set NAME] [--real]
  make_fixture.py results FEED.xml OUT.xml [--inventory true|false] [--omit DEF_SUFFIX] [--odd DEF_SUFFIX=RESULT]
                  [--dup DEF_SUFFIX]

feed: an inventory definition (def:100, Ubuntu 22.04 via /etc/lsb-release, copied from the real feed) plus the
  patch definitions below. --real points every dpkginfo test at the real `bash` package, so a real `oscap oval eval`
  on any Ubuntu 22.04 host gives: 9001 true (known-old: installed bash < 99:1.0), 9002 true (esm pocket, same
  bash < 99:1.0), 9003 false (fixed package: installed bash >= 0:1.0), 9004 false (package not installed).
results: the evaluation a real oscap would write for that feed: definitions marked "true" in the feed comment
  'expect=true' are true, the rest false; dpkginfo items for each true test.
"""
import sys
from xml.sax.saxutils import escape

P = "oval:com.ubuntu.jammy"
# suffix, usn, title, severity, cves, pocket, source, binaries, fixed version (stub), fixed version (real), expect
DEFS = [
    ("900010000000", "USN-9001-1", "oldpkg vulnerabilities", "High", ["CVE-2099-0001", "CVE-2099-0002"], "jammy", "oldpkg",
     ["oldpkg", "liboldpkg1"], "2.0-1ubuntu0.1", "99:1.0", "true"),
    ("900020000000", "USN-9002-1", "esmpkg vulnerability", "Medium", ["CVE-2099-0003"], "esm-apps/jammy", "esmpkg",
     ["esmpkg"], "1.0-1+esm1", "99:1.0", "true"),
    ("900030000000", "USN-9003-1", "fixedpkg vulnerability", "Critical", ["CVE-2099-0004"], "jammy", "fixedpkg",
     ["fixedpkg"], "1.0-1ubuntu0.1", "0:1.0", "false"),
    ("900040000000", "USN-9004-1", "absentpkg regression", "None", [], "jammy", "absentpkg",
     ["pft-vulnscan-no-such-package"], "1.0-2", "99:1.0", "false"),
]
INSTALLED = {"oldpkg": "0:1.0-1", "liboldpkg1": "0:1.0-1", "esmpkg": "0:1.0-1"}

HEAD = """<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:ind-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:unix-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd">
  <generator>
    <oval:product_name>Canonical OVAL Generator</oval:product_name>
    <oval:product_version>2</oval:product_version>
    <oval:schema_version>5.11.1</oval:schema_version>
    <oval:timestamp>{ts}</oval:timestamp>
  </generator>
  <definitions>
    <definition id="{P}:def:100" class="inventory" version="1">
      <metadata>
        <title>Check that Ubuntu 22.04 LTS (jammy) is installed.</title>
        <description />
      </metadata>
      <criteria>
        <criterion test_ref="{P}:tst:100" comment="The host is part of the unix family." />
        <criterion test_ref="{P}:tst:101" comment="The host is running Ubuntu 22.04 LTS (jammy)." />
      </criteria>
    </definition>
"""


def feed(out, ts, real):
    w = [HEAD.format(ts=ts, P=P)]
    for s, usn, title, sev, cves, pocket, src, bins, fixed, rfixed, expect in DEFS:
        fx = rfixed if real else fixed
        refs = "".join(f'        <reference source="CVE" ref_id="{c}" ref_url="https://www.cve.org/CVERecord?id={c}" />\n' for c in cves)
        cvex = "".join(f'          <cve href="https://ubuntu.com/security/{c}" priority="high" public="20990101">{c}</cve>\n' for c in cves)
        w.append(f"""    <definition id="{P}:def:{s}" class="patch" version="1">
      <metadata>
        <title>{usn} -- {escape(title)}</title>
        <affected family="unix">
          <platform>Ubuntu 22.04 LTS</platform>
        </affected>
        <reference source="USN" ref_id="{usn}" ref_url="https://ubuntu.com/security/notices/{usn}" />
{refs}        <description>fixture expect={expect}</description>
        <advisory from="security@ubuntu.com">
          <severity>{sev}</severity>
          <rights>fixture</rights>
          <issued date="2099-01-01T00:00:00Z" />
{cvex}        </advisory>
      </metadata>
      <criteria>
        <extend_definition definition_ref="{P}:def:100" comment="Ubuntu 22.04 LTS (jammy) is installed" applicability_check="true" />
        <criterion test_ref="{P}:tst:{s}" comment="{src} source package in {pocket}, is affected and has been fixed (note: '{escape(fx)}')." />
      </criteria>
    </definition>
""")
    w.append("""  </definitions>
  <tests>
    <ind-def:family_test id="{P}:tst:100" version="1" check="at least one" check_existence="at_least_one_exists" comment="Is the host part of the unix family?">
      <ind-def:object object_ref="{P}:obj:100" />
      <ind-def:state state_ref="{P}:ste:100" />
    </ind-def:family_test>
    <ind-def:textfilecontent54_test id="{P}:tst:101" version="1" check="at least one" check_existence="at_least_one_exists" comment="Is the host running Ubuntu trusty?">
      <ind-def:object object_ref="{P}:obj:101" />
      <ind-def:state state_ref="{P}:ste:101" />
    </ind-def:textfilecontent54_test>
""".format(P=P))
    for d in DEFS:
        s, src = d[0], d[6]
        w.append(f"""    <linux-def:dpkginfo_test id="{P}:tst:{s}" version="1" check="at least one" check_existence="at_least_one_exists" comment="Does the '{src}' package exist?">
      <linux-def:object object_ref="{P}:obj:{s}" />
      <linux-def:state state_ref="{P}:ste:{s}" />
    </linux-def:dpkginfo_test>
""")
    w.append(f"""  </tests>
  <objects>
    <ind-def:family_object id="{P}:obj:100" version="1" comment="The singleton family object" />
    <ind-def:textfilecontent54_object id="{P}:obj:101" version="1">
      <ind-def:filepath datatype="string">/etc/lsb-release</ind-def:filepath>
      <ind-def:pattern operation="pattern match">^[\\s\\S]*DISTRIB_CODENAME=([a-z]+)$</ind-def:pattern>
      <ind-def:instance datatype="int">1</ind-def:instance>
    </ind-def:textfilecontent54_object>
""")
    for d in DEFS:
        w.append(f"""    <linux-def:dpkginfo_object id="{P}:obj:{d[0]}" version="1" comment="The '{d[6]}' package binaries">
      <linux-def:name var_ref="{P}:var:{d[0]}" var_check="at least one" />
    </linux-def:dpkginfo_object>
""")
    w.append(f"""  </objects>
  <states>
    <ind-def:family_state id="{P}:ste:100" version="1" comment="The singleton family state">
      <ind-def:family>unix</ind-def:family>
    </ind-def:family_state>
    <ind-def:textfilecontent54_state id="{P}:ste:101" version="1" comment="Ubuntu 22.04 LTS">
      <ind-def:subexpression datatype="string" operation="equals">jammy</ind-def:subexpression>
    </ind-def:textfilecontent54_state>
""")
    for d in DEFS:
        fx = escape(d[9] if real else d[8])
        w.append(f"""    <linux-def:dpkginfo_state id="{P}:ste:{d[0]}" version="1" comment="The binary package version is less than '{fx}'">
      <linux-def:evr datatype="debian_evr_string" operation="less than">{fx}</linux-def:evr>
    </linux-def:dpkginfo_state>
""")
    w.append("  </states>\n  <variables>\n")
    for d in DEFS:
        bins = ["bash"] if real and d[0] != "900040000000" else d[7]
        vals = "".join(f"      <value>{b}</value>\n" for b in bins)
        w.append(f'    <constant_variable id="{P}:var:{d[0]}" version="1" datatype="string" comment="The \'{d[6]}\' package binaries">\n{vals}    </constant_variable>\n')
    w.append("  </variables>\n</oval_definitions>\n")
    open(out, "w").write("".join(w))


def results(out, inventory, omit, odd, dup):
    R = "http://oval.mitre.org/XMLSchema/oval-results-5"
    defs, tests, items, n = [], [], [], 1000
    defs.append(f'        <definition definition_id="{P}:def:100" result="{inventory}" version="1"/>')
    for d in DEFS:
        s, expect = d[0], d[10]
        if s == omit:
            continue
        res = odd.get(s, expect)
        defs.append(f'        <definition definition_id="{P}:def:{s}" result="{res}" version="1">\n'
                    f'          <criteria operator="AND" result="{res}">\n'
                    f'            <criterion test_ref="{P}:tst:{s}" version="1" result="{res}"/>\n'
                    f'          </criteria>\n        </definition>')
        if s == dup:
            defs.append(defs[-1])
        if res == "true":
            ti = []
            for b in d[7]:
                n += 1
                ti.append(f'          <tested_item item_id="{n}" result="true"/>')
                items.append(f'          <lin-sys:dpkginfo_item id="{n}" status="exists">\n'
                             f'            <lin-sys:name>{b}</lin-sys:name>\n'
                             f'            <lin-sys:evr datatype="debian_evr_string">{INSTALLED.get(b, "0:1.0-1")}</lin-sys:evr>\n'
                             f'          </lin-sys:dpkginfo_item>')
            tests.append(f'        <test test_id="{P}:tst:{s}" version="1" check="at least one" result="true">\n' + "\n".join(ti) + "\n        </test>")
        else:
            tests.append(f'        <test test_id="{P}:tst:{s}" version="1" check="at least one" result="false"/>')
    doc = (f'<?xml version="1.0" encoding="UTF-8"?>\n<oval_results xmlns="{R}" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">\n'
           f'  <results>\n    <system>\n      <definitions>\n' + "\n".join(defs) + "\n      </definitions>\n      <tests>\n"
           + "\n".join(tests) + "\n      </tests>\n"
           '      <oval_system_characteristics xmlns="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5" '
           'xmlns:lin-sys="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux">\n        <system_data>\n'
           + "\n".join(items) + "\n        </system_data>\n      </oval_system_characteristics>\n    </system>\n  </results>\n</oval_results>\n")
    open(out, "w").write(doc)


def main(a):
    if a[0] == "feed":
        ts, real = "2099-01-01T00:00:00", False
        i = 2
        while i < len(a):
            if a[i] == "--ts":
                ts = a[i + 1]; i += 2
            elif a[i] == "--real":
                real = True; i += 1
            else:
                sys.exit(f"bad arg {a[i]}")
        feed(a[1], ts, real)
    elif a[0] == "results":
        inv, omit, odd, dup = "true", None, {}, None
        i = 3
        while i < len(a):
            k, v = a[i], a[i + 1]; i += 2
            if k == "--inventory":
                inv = v
            elif k == "--omit":
                omit = v
            elif k == "--odd":
                s, r = v.split("="); odd[s] = r
            elif k == "--dup":
                dup = v
            else:
                sys.exit(f"bad arg {k}")
        results(a[2], inv, omit, odd, dup)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
