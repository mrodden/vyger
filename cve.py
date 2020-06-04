
import json
import re
import xml.etree.ElementTree as ET


class Definition(object):
    """
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

def parse(file_name):

    with open(file_name) as xmlfile:
        tree = ET.parse(xmlfile)

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

    print(json.dumps(list(map(Definition.to_dict, defs))))


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
                "fix_available": False,
            }
            packs.append(package)

        m = fix_avail.search(comment)
        if m:
            package = {
                "name": m.group("package"),
                "version": m.group("version"),
            }
            packs.append(package)

        m = undecided.search(comment)
        if m:
            package = {
                "name": m.group("package"),
                "fix_available": False,
            }
            packs.append(package)


if __name__ == "__main__":
    parse("./com.ubuntu.bionic.cve.oval.xml")
