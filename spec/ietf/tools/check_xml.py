#!/usr/bin/env python3
"""Reject empty, malformed, unresolved, or placeholder-bearing draft XML."""
import sys
from pathlib import Path
from html.entities import name2codepoint
import xml.etree.ElementTree as ET


def check(path):
    data = Path(path).read_text()
    # RFCXML's DTD defines typographic entities. Expand only the known
    # characters locally; never fetch or resolve an external DTD here.
    for name, codepoint in name2codepoint.items():
        data = data.replace(f"&{name};", f"&#{codepoint};")
    for name, codepoint in {"nbhy": 0x2011, "zwsp": 0x200b, "wj": 0x2060}.items():
        data = data.replace(f"&{name};", f"&#{codepoint};")
    root = ET.fromstring(data)
    if root.tag != "rfc" or not root.findtext("front/title"):
        raise ValueError("not a complete RFCXML document")
    for element in root.iter():
        if element.tag == "reference" and (
            "BROKEN" in "".join(element.itertext())
            or not element.findtext("front/title")
        ):
            raise ValueError("unresolved bibliographic reference")
    text = "".join(root.itertext())
    if "This section is being written" in text:
        raise ValueError("unfinished draft section")


if __name__ == "__main__":
    for filename in sys.argv[1:]:
        try:
            check(filename)
        except (OSError, ET.ParseError, ValueError) as error:
            print(f"check_xml: {filename}: {error}", file=sys.stderr)
            sys.exit(1)
