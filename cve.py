# Copyright 2020 Mathew Odden
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import bz2
import json
import platform
import re
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET


class Definition(object):
    """
    Attributes:
        id
        definition_id
        title
        description
        advisory
        debian
        affected_packs
        references
    """

    def __init__(self):
        self.id = ""

    def __repr__(self):
        return "<Definition(CVE='%s', severity='%s', affected_packs=%r)>" % (self.debian.get("cve_id"), self.advisory.get("severity"), self.affected_packs)

    def to_dict(self):
        this = {
            "id": self.id,
            "definition_id": self.definition_id,
            "title": self.title,
            "description": self.description,
            "advisory": self.advisory,
            "debian": self.debian,
            "affected_packs": self.affected_packs,
            "references": self.references,
        }
        return this


default_ns = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"


def parse(data_file):

    if isinstance(data_file, str):
        with open(data_file) as xmlfile:
            tree = ET.parse(xmlfile)
    else:
        tree = ET.parse(data_file)

    root = tree.getroot()

    defs = []
    for xdef in root.iter(default_ns + "definition"):

        cve_id = ""
        severity = ""
        refs = []

        for xref in xdef.iter(default_ns + "reference"):
            ref = {
                "source": xref.get("source"),
                "ref_id": xref.get("ref_id"),
                "ref_url": xref.get("ref_url"),
            }
            if ref["source"] == "CVE":
                cve_id = ref["ref_id"]

            refs.append(ref)


        advisory = xdef.find("%smetadata/%sadvisory" % (default_ns, default_ns))
        if advisory:
            sev = advisory.find(default_ns + "severity")
            if sev is not None and sev.text is not None:
                severity = sev.text

            for xref in advisory.iter(default_ns + "ref"):
                ref = {
                    "source": "ref",
                    "ref_url": xref.text,
                }
                refs.append(ref)

            for xref in advisory.iter(default_ns + "bug"):
                ref = {
                    "source": "ref",
                    "ref_url": xref.text,
                }
                refs.append(ref)

        df = Definition()
        df.definition_id = xdef.get("id")

        metadata = xdef.find(default_ns + "metadata")

        title = metadata.find(default_ns + "title")
        if title is not None:
            df.title = title.text
        else:
            df.title = ""

        description = metadata.find(default_ns + "description")
        if description is not None:
            df.description = description.text
        else:
            df.description = ""

        df.references = refs

        df.advisory = {"severity": severity}
        df.debian = {"cve_id": cve_id}

        packs = []
        scrape_pack_data(packs, xdef.find(default_ns + "criteria"))
        df.affected_packs = packs

        defs.append(df)

    return defs


needs_fix = re.compile(r"^(?P<package>.+) package in .+ affected and needs fixing.$")
fix_avail = re.compile(r"^(?P<package>.+) package in .+ has been fixed \(note: '(?P<version>[^\s]+).*'\).$")
undecided = re.compile(r"^(?P<package>.+) package in .+ is affected, but a decision has been made to defer addressing it .+$")


def scrape_pack_data(packs, criteria):

    for crit in criteria.iter(default_ns + "criterion"):
        if crit.get("negate"):
            continue

        comment = crit.get("comment")

        m = needs_fix.search(comment)
        if m:
            package = {
                "name": m.group("package"),
                "version": None,
                "fix_available": False,
            }
            packs.append(package)

        m = fix_avail.search(comment)
        if m:
            package = {
                "name": m.group("package"),
                "version": m.group("version"),
                "fix_available": True,
            }
            packs.append(package)

        m = undecided.search(comment)
        if m:
            package = {
                "name": m.group("package"),
                "version": None,
                "fix_available": False,
            }
            packs.append(package)


def fetch_oval(codename):
    """
    Fetches OVAL data for a given release of Ubuntu.

    Args:
        codename (str): should be the name of the release, e.g. 'trusty', 'bionic', etc

    Returns:
        object: a file-like object which holds the OVAL defintion data

    """

    url = "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml.bz2" % codename

    tmpfile = tempfile.TemporaryFile()

    decomp = bz2.BZ2Decompressor()

    oval_data = None
    with urllib.request.urlopen(url) as oval_file:
        if oval_file.getcode() != 200:
            raise Exception("Error fetching OVAL file: HTTP GET returned '%s'" % oval_file.reason)

        while True:
            data = oval_file.read(4096)
            if data:
                _data = decomp.decompress(data)
                tmpfile.write(_data)
            else:
                assert decomp.eof
                break

    # reset to beginning
    tmpfile.seek(0)

    return tmpfile


def run_cmd(args):

    p = subprocess.Popen(
        args,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    out, err = p.communicate()
    rc = p.returncode

    return out, err, rc


class Package(object):

    _cache = {}

    def __init__(self, name):
        self.name = name

    def _get_sysinfo(self):
        pkginfo = self._cache.get(self.name, {})

        if not pkginfo or "installed" not in pkginfo or "installed_version" not in pkginfo:
            out, err, rc = run_cmd(["dpkg", "-s", self.name])

            if rc != 0:
                dpkg_query_err = err.decode("utf-8").split("\n")[0]
                if "not installed" in dpkg_query_err:
                    installed = False
                    version = None
                else:
                    raise Exception("error getting package info: out=%r, err=%r, rc=%r" % (out, err, rc))
            else:
                for line in out.decode("utf-8").split("\n"):
                    if line.startswith("Version:"):
                        _, version = line.split(":", 1)
                        installed = True
                        version = version.strip()

            pkginfo["installed"] = installed
            pkginfo["installed_version"] = version

            #print("Package %s installed=%s version=%s" % (self.name, installed, version), file=sys.stderr)

            self._cache[self.name] = pkginfo

        return pkginfo

    @property
    def installed(self):
        return self._get_sysinfo()["installed"]

    @property
    def installed_version(self):
        return self._get_sysinfo()["installed_version"]

    def installed_version_less_than(self, version):
        if not self.installed:
            return False

        out, err, rc = run_cmd(["dpkg", "--compare-versions", self.installed_version, "lt", version])

        # there should be no output
        if err or out:
            raise Exception("Got stdout/stderr on version check: out=%r, err=%r, rc=%r" % (out, err, rc))

        # dpkg --compare-versions returns 0 for True, 1 for False
        if rc == 0:
            return True
        else:
            return False


def needs_update(defn):
    for pack in defn.affected_packs:

        p = Package(pack.get("name"))

        if not pack.get("fix_available") and p.installed:
            continue

        if p.installed_version_less_than(pack.get("version")):
            return "'%s' is at %s, need %s or later" % (pack.get("name"), p.installed_version, pack.get("version"))

    return None


def main():

    family, _, codename = platform.linux_distribution()

    if family != "Ubuntu":
        sys.exit("Only Ubuntu linux is supported at the moment.")

    oval_items = None

    try:
        data_file = fetch_oval(codename)
        oval_items = parse(data_file)
    finally:
        data_file.close()

    if oval_items:
        for item in oval_items:
            msg = needs_update(item)
            if msg:
                print("%s Alert: %s" % (item.title, msg))


if __name__ == "__main__":
    main()
