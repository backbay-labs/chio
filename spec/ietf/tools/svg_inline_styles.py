#!/usr/bin/env python3
"""Rewrite aasvg output for the RFC 7996 SVG profile.

aasvg styles its drawing with a <style> element, which the profile does not
allow. This moves each rule onto the elements it matches as presentation
attributes and removes the element. Reads SVG on stdin, writes it on stdout.
"""
import re
import sys

LINE = {"fill": "none", "stroke": "black", "stroke-linecap": "round"}
# The profile allows no stroke attribute on polygon or text; SVG draws neither
# with a stroke by default.
FILLED = {"fill": "black"}
TEXT = {
    "font-family": "monospace",
    "font-size": "13px",
    "text-anchor": "middle",
    "fill": "black",
}


def classes(tag):
    match = re.search(r'\bclass="([^"]*)"', tag)
    return set(match.group(1).split()) if match else set()


def with_attrs(tag, attrs):
    missing = {k: v for k, v in attrs.items() if not re.search(rf'\s{re.escape(k)}="', tag)}
    if not missing:
        return tag
    extra = "".join(f' {k}="{v}"' for k, v in missing.items())
    end = "/>" if tag.endswith("/>") else ">"
    return tag[: -len(end)] + extra + end


def rewrite(match):
    tag = match.group(0)
    name = match.group(1)
    cls = classes(tag)
    if name == "text":
        attrs = dict(TEXT)
        if "b" in cls:
            attrs["font-weight"] = "700"
        if "i" in cls:
            attrs["font-style"] = "italic"
        return with_attrs(tag, attrs)
    if name == "polygon" or cls & {"arrowhead", "triangle", "closeddot"}:
        return with_attrs(tag, FILLED)
    if "opendot" in cls:
        return with_attrs(tag, {"fill": "white", "stroke": "black"})
    attrs = dict(LINE)
    if "dashed" in cls:
        attrs["stroke-dasharray"] = "3,6"
    return with_attrs(tag, attrs)


svg = sys.stdin.read()
svg = re.sub(r"<style>.*?</style>\n?", "", svg, flags=re.S)
svg = re.sub(r"<(path|line|polyline|polygon|circle|ellipse|rect|text)\b[^>]*>", rewrite, svg)
sys.stdout.write(svg)
