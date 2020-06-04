
import re
import json

from lxml import etree, objectify


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


def parse(file_name):

    with open(file_name) as xmlfile:
        tree = objectify.parse(xmlfile)

    root = tree.getroot()

    defs = []
    for xdef in root.definitions.definition:

        cve_id = ""
        severity = ""
        refs = []

        for xref in xdef.metadata.findall("{*}reference"):
            ref = {
                "source": xref.get("source"),
                "ref_id": xref.get("ref_id"),
                "ref_url": xref.get("ref_url"),
            }
            if ref["source"] == "CVE":
                cve_id = ref["ref_id"]

            refs.append(ref)


        advisories = xdef.metadata.findall("{*}advisory")
        if advisories:
            severity = str(xdef.metadata.advisory.severity)

            for xref in xdef.metadata.advisory.ref:
                ref = {
                    "source": "ref",
                    "ref_url": str(xref),
                }
                refs.append(ref)

            for xref in xdef.metadata.advisory.findall("{*}bug"):
                ref = {
                    "source": "ref",
                    "ref_url": str(xref),
                }
                refs.append(ref)

        df = Definition()
        df.definition_id = xdef.get("id")

        try:
            df.title = xdef.metadata.title.text
        except AttributeError:
            df.title = ""

        try:
            df.description = xdef.metadata.description.text
        except AttributeError:
            df.description = ""

        df.references = refs

        df.advisory = {"severity": severity}
        df.debian = {"cve_id": cve_id}

        packs = []
        scrape_pack_data(packs, xdef.criteria)
        df.affected_packs = packs

        defs.append(df)

    print(json.dumps(list(map(Definition.to_dict, defs))))


needs_fix = re.compile(r"^(?P<package>.+) package in .+ affected and needs fixing.$")
fix_avail = re.compile(r"^(?P<package>.+) package in .+ has been fixed \(note: '(?P<version>[^\s]+).*'\).$")
undecided = re.compile(r"^(?P<package>.+) package in .+ is affected, but a decision has been made to defer addressing it .+$")


def scrape_pack_data(packs, criteria):

    for crit in criteria.findall(".//{*}criterion"):
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
