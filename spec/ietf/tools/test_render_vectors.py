#!/usr/bin/env python3
"""Self-test for render_vectors.py.

Run it with plain `python3 test_render_vectors.py` or with `python3 -m pytest`.
It uses only the standard library. The Ed25519 code below is the reference
algorithm of RFC 8032 section 6, used only to check signatures in the corpus;
it is slow and not constant-time.
"""
import contextlib
import hashlib
import io
import json
import pathlib
import random
import re
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import render_vectors as rv  # noqa: E402

IETF = HERE.parent
VECTORS = HERE.parents[2] / "tests" / "bindings" / "vectors"
GENERATED = IETF / "generated"
DRAFT = IETF / "draft-whelan-chio-protocol.md"
SCRIPT = HERE / "render_vectors.py"


# ---------------------------------------------------------------------------
# Ed25519, RFC 8032 section 6.
# ---------------------------------------------------------------------------
_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    p1 = (a[1] - a[0]) * (b[1] - b[0]) % _P
    p2 = (a[1] + a[0]) * (b[1] + b[0]) % _P
    c = 2 * a[3] * b[3] * _D % _P
    d = 2 * a[2] * b[2] % _P
    e, f, g, h = p2 - p1, d - c, d + c, p2 + p1
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, point):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, point)
        point = _add(point, point)
        s >>= 1
    return q


def _same(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(point):
    zinv = _inv(point[2])
    x = point[0] * zinv % _P
    y = point[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def ed25519_public_from_seed(seed):
    digest = hashlib.sha512(seed).digest()
    a = int.from_bytes(digest[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _compress(_mul(a, _G))


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a_point = _decompress(public)
    r_point = _decompress(signature[:32])
    if a_point is None or r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _Q
    return _same(_mul(s, _G), _add(r_point, _mul(h, a_point)))


def verify_hex(public_hex, message, signature_hex):
    return ed25519_verify(bytes.fromhex(public_hex), message, bytes.fromhex(signature_hex))


# ---------------------------------------------------------------------------
# Independent verifiers for the corpus objects.
# ---------------------------------------------------------------------------
def verify_capability(cap, now):
    """Return the four-member report that the corpus records for a token."""
    signing = {k: v for k, v in cap.items() if k != "signature"}
    signing["schema"] = "chio.capability.v1"
    chain = cap.get("delegation_chain", [])
    chain_ok = True
    for i, link in enumerate(chain):
        link_body = {k: v for k, v in link.items() if k != "signature"}
        if not verify_hex(link["delegator"], rv.canonical_bytes(link_body), link["signature"]):
            chain_ok = False
            break
        if i > 0 and (
            chain[i - 1]["delegatee"] != link["delegator"]
            or link["timestamp"] < chain[i - 1]["timestamp"]
        ):
            chain_ok = False
            break
    if now < cap["issued_at"]:
        status = "not_yet_valid"
    elif now >= cap["expires_at"]:
        status = "expired"
    else:
        status = "valid"
    return {
        "signature_valid": verify_hex(cap["issuer"], rv.canonical_bytes(signing), cap["signature"]),
        "delegation_chain_shape_valid": chain_ok,
        "time_valid": status == "valid",
        "time_status": status,
    }


def receipt_body(receipt):
    return {k: v for k, v in receipt.items() if k not in ("id", "signature")}


def receipt_checks(receipt):
    body = receipt_body(receipt)
    id_valid = hashlib.sha256(rv.canonical_bytes(body)).hexdigest() == receipt["id"]
    signing = {"id": receipt["id"], "body": body}
    return {
        "receipt_id_valid": id_valid,
        "signature_valid": id_valid
        and verify_hex(receipt["kernel_key"], rv.canonical_bytes(signing), receipt["signature"]),
        "parameter_hash_valid": hashlib.sha256(
            rv.canonical_bytes(receipt["action"]["parameters"])
        ).hexdigest()
        == receipt["action"]["parameter_hash"],
    }


# ---------------------------------------------------------------------------
# Corpus access and fragment parsing.
# ---------------------------------------------------------------------------
def load(name):
    with open(VECTORS / name / "v1.json", encoding="utf-8") as handle:
        return json.load(handle)


def by_id(cases):
    return {case["id"]: case for case in cases}


def contains_float(value):
    if isinstance(value, float):
        return True
    if isinstance(value, list):
        return any(contains_float(item) for item in value)
    if isinstance(value, dict):
        return any(contains_float(item) for item in value.values())
    return False


FENCE = re.compile(r"^~~~(?: (\S+))?$")
HEADING = re.compile(r"^## (.+) \{#([a-z0-9-]+)\}$")
PROVENANCE = re.compile(
    r"The following case is `([a-z]+/v1\.json)` case `([a-z0-9_]+)` "
    r"from the Chio binding vector corpus\."
)


def parse_fragment(text):
    """Split a fragment into intro paragraphs and sections.

    Returns (intro, sections). Each section is a dict with the keys "title",
    "anchor", and "items"; an item is ("p", paragraph) or ("b", lang, content).
    Blocks carry their folded text exactly as written in the fragment.
    """
    lines = text.split("\n")
    intro, sections = [], []
    paragraph = []
    i = 0

    def target():
        return sections[-1]["items"] if sections else intro

    def flush():
        if paragraph:
            target().append(("p", " ".join(paragraph)))
            paragraph.clear()

    while i < len(lines):
        line = lines[i]
        fence = FENCE.match(line)
        heading = HEADING.match(line)
        if fence:
            flush()
            j = i + 1
            body = []
            while lines[j] != "~~~":
                body.append(lines[j])
                j += 1
            target().append(("b", fence.group(1), "\n".join(body)))
            i = j + 1
            continue
        if heading:
            flush()
            sections.append({"title": heading.group(1), "anchor": heading.group(2), "items": []})
        elif line == "":
            flush()
        else:
            paragraph.append(line)
        i += 1
    flush()
    return intro, sections


def groups(section):
    """Split a test-vector section into per-case groups keyed by provenance."""
    result = []
    for item in section["items"]:
        if item[0] == "p":
            match = PROVENANCE.search(item[1])
            if match:
                result.append({"file": match.group(1), "id": match.group(2), "items": [item]})
                continue
        if result:
            result[-1]["items"].append(item)
    return result


def blocks_of(items):
    return [(item[1], rv.unfold(item[2])) for item in items if item[0] == "b"]


def text_of(items):
    return " ".join(item[1] for item in items if item[0] == "p")


def octets(data):
    return " ".join("%02x" % b for b in data)


_RENDERED = {}


def rendered():
    if not _RENDERED:
        _RENDERED.update(rv.render_all(VECTORS))
    return _RENDERED


# ---------------------------------------------------------------------------
# RFC 8792 folding.
# ---------------------------------------------------------------------------
class FoldTests(unittest.TestCase):
    def test_header_is_exact_and_69_columns(self):
        header = rv.fold_header()
        self.assertEqual(
            header, "=============== NOTE: '\\' line wrapping per RFC 8792 ================"
        )
        self.assertEqual(len(header), 69)
        self.assertEqual(len(rv.FOLD_HEADER_TEXT), 36)

    def test_200_character_line_folds_and_unfolds(self):
        line = "".join(str(i % 10) for i in range(200))
        folded = rv.fold(line)
        self.assertNotEqual(folded, line)
        lines = folded.split("\n")
        self.assertEqual(lines[0], rv.fold_header())
        self.assertEqual(lines[1], "")
        self.assertTrue(all(len(x) <= 69 for x in lines))
        self.assertTrue(all(x.endswith("\\") for x in lines[2:-1]))
        self.assertFalse(lines[-1].endswith("\\"))
        self.assertEqual(rv.unfold(folded), line)

    def test_matches_the_rfc_8792_example_of_a_280_character_line(self):
        # RFC 8792 section 9.2.1, single backslash strategy, column 69.
        line = "1234567890" * 28
        folded = rv.fold(line).split("\n")
        self.assertEqual(
            folded[2:],
            [
                "12345678901234567890123456789012345678901234567890123456789012345678\\",
                "90123456789012345678901234567890123456789012345678901234567890123456\\",
                "78901234567890123456789012345678901234567890123456789012345678901234\\",
                "56789012345678901234567890123456789012345678901234567890123456789012\\",
                "34567890",
            ],
        )

    def test_text_that_fits_is_returned_unchanged(self):
        text = "x" * 69 + "\nshort"
        self.assertEqual(rv.fold(text), text)
        self.assertEqual(rv.unfold(text), text)

    def test_a_line_of_70_characters_is_folded(self):
        line = "a" * 70
        folded = rv.fold(line).split("\n")
        self.assertEqual(folded[2], "a" * 68 + "\\")
        self.assertEqual(folded[3], "aa")

    def test_only_long_lines_change_in_a_multi_line_text(self):
        text = "short\n" + "b" * 100 + "\nend"
        folded = rv.fold(text).split("\n")
        self.assertEqual(folded[2], "short")
        self.assertEqual(folded[-1], "end")
        self.assertEqual(rv.unfold("\n".join(folded)), text)

    def test_a_token_that_fits_on_a_line_is_never_split(self):
        # Folds fall after a comma or a colon, and only a value too long for any
        # line is cut in the middle.
        keys = ["%064x" % (i * 7919 + 12345) for i in range(6)]
        line = json.dumps({"k%d" % i: key for i, key in enumerate(keys)}, separators=(",", ":"))
        folded = rv.fold(line)
        shown = folded.split("\n")[2:]
        for key in keys:
            self.assertEqual(sum(key in row for row in shown), 1, key)
        for row in shown[:-1]:
            self.assertTrue(row.endswith((",\\", ":\\")), row)
        self.assertEqual(rv.unfold(folded), line)

    def test_a_value_longer_than_a_line_is_cut_where_the_line_ends(self):
        long_value = "ab" * 100
        line = '{"first":"1","signature":"%s","last":2}' % long_value
        folded = rv.fold(line)
        shown = folded.split("\n")[2:]
        self.assertTrue(all(len(row) <= 69 for row in shown))
        self.assertEqual(len(shown[0]), 69)
        self.assertTrue(shown[0].endswith("\\"))
        self.assertGreaterEqual(sum(set(row) <= set("ab\\") for row in shown), 2)
        self.assertEqual(rv.unfold(folded), line)

    def test_pretty_lines_fold_after_the_colon_and_its_space(self):
        line = '      "delegatee": "' + "9" * 40 + '", "other": "' + "8" * 40 + '"'
        folded = rv.fold(line, extra_indent=4)
        rows = folded.split("\n")[2:]
        self.assertTrue(all(len(row) <= 69 for row in rows))
        for previous, following in zip(rows, rows[1:]):
            self.assertTrue(previous.endswith("\\"))
            self.assertFalse(following.lstrip(" ").startswith(" "))
        self.assertEqual(rv.unfold(folded), line)

    def test_a_fold_is_never_placed_before_a_space(self):
        # Spaces sit on every column where the fold would fall.
        for period in (2, 3, 4, 7):
            line = "".join("x" if i % period else " " for i in range(300)).strip()
            folded = rv.fold(line)
            for current in folded.split("\n")[2:-1]:
                self.assertTrue(current.endswith("\\"))
            body = folded.split("\n")[2:]
            for previous, following in zip(body, body[1:]):
                if previous.endswith("\\"):
                    self.assertFalse(following.startswith(" "), (period, following))
            self.assertEqual(rv.unfold(folded), line)

    def test_a_chunk_never_ends_with_a_content_backslash(self):
        line = ("a" * 66 + "\\\\") * 4 + "tail"
        folded = rv.fold(line)
        for current in folded.split("\n")[2:-1]:
            self.assertTrue(current.endswith("\\"))
            self.assertFalse(current.endswith("\\\\"), current)
        self.assertEqual(rv.unfold(folded), line)

    def test_a_long_run_of_backslashes_cannot_be_folded(self):
        with self.assertRaises(rv.FoldError):
            rv.fold("\\" * 200)

    def test_a_line_that_ends_with_a_backslash_is_rejected(self):
        with self.assertRaises(rv.FoldError):
            rv.fold("a" * 100 + "\\")
        with self.assertRaises(rv.FoldError):
            rv.fold("a" * 100 + "\nshort\\")

    def test_tabs_and_non_ascii_are_rejected(self):
        with self.assertRaises(rv.FoldError):
            rv.fold("a\tb")
        with self.assertRaises(rv.FoldError):
            rv.fold("a" * 100 + "\U000000e9")

    def test_continuation_lines_are_indented_and_unfold_exactly(self):
        pretty = json.dumps({"k": {"signature": "ab" * 64, "n": 1}}, indent=2)
        folded = rv.fold(pretty, extra_indent=4)
        lines = folded.split("\n")
        self.assertTrue(all(len(x) <= 69 for x in lines))
        continuation = [
            cur for prev, cur in zip(lines[2:], lines[3:]) if prev.endswith("\\")
        ]
        self.assertTrue(continuation)
        self.assertTrue(all(x.startswith(" " * 8) for x in continuation))
        self.assertEqual(rv.unfold(folded), pretty)

    def test_a_folded_text_survives_the_indentation_that_xml2rfc_adds(self):
        folded = rv.fold("z" * 500)
        self.assertTrue(all(len("   " + x) <= 72 for x in folded.split("\n")))

    def test_unfold_leaves_text_without_the_header_alone(self):
        text = "a\\\n  b"
        self.assertEqual(rv.unfold(text), text)

    def test_unfold_accepts_any_printable_surroundings_of_the_header(self):
        text = "[NOTE: '\\' line wrapping per RFC 8792]\n\nabc\\\n   def"
        self.assertEqual(rv.unfold(text), "abcdef")

    def test_unfold_rejects_a_fold_marker_on_the_last_line(self):
        with self.assertRaises(rv.FoldError):
            rv.unfold(rv.fold_header() + "\n\nabc\\")

    def test_round_trip_of_random_text(self):
        rng = random.Random(8792)
        alphabet = "ab0 \\\"{}:,[]"
        for trial in range(300):
            lines = []
            for _ in range(rng.randint(1, 4)):
                lead = " " * rng.randint(0, 6)
                body = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 260)))
                lines.append((lead + body).rstrip("\\"))
            text = "\n".join(lines)
            for width, indent in ((69, 0), (69, 4), (45, 2), (40, 0)):
                try:
                    folded = rv.fold(text, width=width, extra_indent=indent)
                except rv.FoldError:
                    continue
                self.assertTrue(all(len(x) <= width for x in folded.split("\n")), (trial, width))
                self.assertEqual(rv.unfold(folded), text, (trial, width, indent))


# ---------------------------------------------------------------------------
# RFC 8785 canonical JSON.
# ---------------------------------------------------------------------------
class CanonicalJsonTests(unittest.TestCase):
    def test_every_corpus_case_without_floats_is_reproduced(self):
        cases = load("canonical")["cases"]
        checked = []
        for case in cases:
            value = rv.loads_strict(case["input_json"])
            if contains_float(value):
                continue
            self.assertEqual(rv.canonicalize(value), case["canonical_json"], case["id"])
            checked.append(case["id"])
        self.assertGreaterEqual(len(checked), 15)
        self.assertIn("utf16_key_ordering", checked)
        self.assertIn("integer_above_double_precision", checked)
        self.assertNotIn("number_formatting", checked)

    def test_every_corpus_case_with_floats_is_reproduced(self):
        floats = []
        for case in load("canonical")["cases"]:
            value = rv.loads_strict(case["input_json"])
            if contains_float(value):
                self.assertEqual(rv.canonicalize(value), case["canonical_json"], case["id"])
                floats.append(case["id"])
        self.assertIn("number_formatting", floats)

    def test_rfc_8785_section_3_2_2_sample(self):
        # The input of section 3.2.2 and the octets of section 3.2.4.
        source = """{
  "numbers": [333333333.33333329, 1E30, 4.50,
              2e-3, 0.000000000000000000000000001],
  "string": "!u20ac$!u000F!u000aA'!u0042!u0022!u005c!!!"!/",
  "literals": [null, true, false]
}""".replace("!", "\\")
        expected = bytes.fromhex(
            """
            7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72
            75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a
            5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31
            65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37
            5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30
            30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d
            """
        )
        self.assertEqual(rv.canonical_bytes(rv.loads_strict(source)), expected)

    def test_rfc_8785_section_3_2_3_sorting_sample(self):
        source = (
            '{"\\u20ac":"Euro Sign","\\r":"Carriage Return",'
            '"\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One",'
            '"\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control",'
            '"\\u00f6":"Latin Small Letter O With Diaeresis"}'
        )
        canonical = rv.canonicalize(rv.loads_strict(source))
        self.assertEqual(
            list(json.loads(canonical).values()),
            [
                "Carriage Return",
                "One",
                "Control",
                "Latin Small Letter O With Diaeresis",
                "Euro Sign",
                "Emoji: Grinning Face",
                "Hebrew Letter Dalet With Dagesh",
            ],
        )

    def test_rfc_8785_appendix_b_number_samples(self):
        samples = [
            ("0000000000000000", "0"),
            ("8000000000000000", "0"),
            ("0000000000000001", "5e-324"),
            ("8000000000000001", "-5e-324"),
            ("7fefffffffffffff", "1.7976931348623157e+308"),
            ("ffefffffffffffff", "-1.7976931348623157e+308"),
            ("4340000000000000", "9007199254740992"),
            ("c340000000000000", "-9007199254740992"),
            ("4430000000000000", "295147905179352830000"),
            ("44b52d02c7e14af5", "9.999999999999997e+22"),
            ("44b52d02c7e14af6", "1e+23"),
            ("44b52d02c7e14af7", "1.0000000000000001e+23"),
            ("444b1ae4d6e2ef4e", "999999999999999700000"),
            ("444b1ae4d6e2ef4f", "999999999999999900000"),
            ("444b1ae4d6e2ef50", "1e+21"),
            ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
            ("3eb0c6f7a0b5ed8d", "0.000001"),
            ("41b3de4355555553", "333333333.3333332"),
            ("41b3de4355555554", "333333333.33333325"),
            ("41b3de4355555555", "333333333.3333333"),
            ("41b3de4355555556", "333333333.3333334"),
            ("41b3de4355555557", "333333333.33333343"),
            ("becbf647612f3696", "-0.0000033333333333333333"),
            ("43143ff3c1cb0959", "1424953923781206.2"),
        ]
        for ieee, expected in samples:
            value = struct.unpack(">d", bytes.fromhex(ieee))[0]
            self.assertEqual(rv.canonicalize(value), expected, ieee)
        for ieee in ("7fffffffffffffff", "7ff0000000000000"):
            with self.assertRaises(rv.CanonicalizationError):
                rv.canonicalize(struct.unpack(">d", bytes.fromhex(ieee))[0])

    def test_integers_are_written_in_full(self):
        self.assertEqual(rv.canonicalize(9007199254740993), "9007199254740993")
        self.assertEqual(rv.canonicalize(-(2**63)), "-9223372036854775808")
        self.assertEqual(rv.canonicalize(2**64 - 1), "18446744073709551615")
        for outside in (2**64, -(2**63) - 1):
            with self.assertRaises(rv.CanonicalizationError):
                rv.canonicalize(outside)

    def test_booleans_are_not_integers(self):
        self.assertEqual(rv.canonicalize([True, False, 1, 0, None]), "[true,false,1,0,null]")

    def test_string_escaping_follows_section_3_2_2_2(self):
        raw = "\b\t\n\f\r\"\\/" + "\x00\x01\x0b\x0e\x1f" + "\x7f\x80\x9f\U00002028\U000000e9"
        self.assertEqual(
            rv.canonicalize(raw),
            '"\\b\\t\\n\\f\\r\\"\\\\/\\u0000\\u0001\\u000b\\u000e\\u001f'
            '\x7f\x80\x9f\U00002028\U000000e9"',
        )

    def test_keys_are_sorted_by_utf16_code_units_not_utf8_bytes(self):
        value = {"\U0000e000": 1, "\U00010000": 2}
        self.assertEqual(rv.canonicalize(value), '{"\U00010000":2,"\U0000e000":1}')
        self.assertEqual(rv.canonical_bytes({"\U0001f600": 1, "a": 1}), b'{"a":1,"\xf0\x9f\x98\x80":1}')

    def test_sorting_is_recursive_and_leaves_arrays_in_order(self):
        value = {"b": [{"z": 1, "a": [3, 2, 1]}], "a": {"y": None, "x": True}}
        self.assertEqual(
            rv.canonicalize(value), '{"a":{"x":true,"y":null},"b":[{"a":[3,2,1],"z":1}]}'
        )

    def test_empty_containers_and_no_whitespace(self):
        self.assertEqual(rv.canonicalize({"a": {}, "b": []}), '{"a":{},"b":[]}')

    def test_values_without_a_canonical_form_are_rejected(self):
        for bad in (float("nan"), float("inf"), "\ud800", {"\udead": 1}, {1: 2}, {1, 2}, b"x", object()):
            with self.assertRaises(rv.CanonicalizationError, msg=repr(bad)):
                rv.canonicalize(bad)

    def test_the_strict_loader_rejects_duplicate_keys_and_non_finite_numbers(self):
        with self.assertRaises(ValueError):
            rv.loads_strict('{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            rv.loads_strict("NaN")
        with self.assertRaises(ValueError):
            rv.loads_strict("[Infinity]")


class Ed25519ReferenceTests(unittest.TestCase):
    """Check the verifier that the rest of this file relies on."""

    SECRET = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    SIGNATURE = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )

    def test_rfc_8032_test_vector_1(self):
        self.assertEqual(ed25519_public_from_seed(self.SECRET), self.PUBLIC)
        self.assertTrue(ed25519_verify(self.PUBLIC, b"", self.SIGNATURE))

    def test_a_changed_message_or_signature_is_rejected(self):
        self.assertFalse(ed25519_verify(self.PUBLIC, b"x", self.SIGNATURE))
        flipped = bytes([self.SIGNATURE[0] ^ 1]) + self.SIGNATURE[1:]
        self.assertFalse(ed25519_verify(self.PUBLIC, b"", flipped))
        self.assertFalse(ed25519_verify(self.PUBLIC, b"", self.SIGNATURE[:63]))


# ---------------------------------------------------------------------------
# The corpus, as the rendered fragments use it.
# ---------------------------------------------------------------------------
class CorpusClaimTests(unittest.TestCase):
    """The statements that the generated prose makes about the corpus."""

    def test_the_helper_and_the_corpus_agree_on_every_case_shown(self):
        # render_all raises if they do not, so this also guards the renderer.
        self.assertEqual(sorted(rendered()), ["appendix-a.md", "appendix-b.md"])

    def test_every_key_in_the_selected_cases_derives_from_a_published_seed(self):
        capability = load("capability")
        receipt = load("receipt")
        signing = load("signing")
        cap = by_id(capability["cases"])["valid_delegated_capability"]["capability"]
        link = cap["delegation_chain"][0]
        shown = {
            "issuer": (cap["issuer"], [capability["issuer_seed_hex"]]),
            "subject": (cap["subject"], [capability["subject_seed_hex"]]),
            "delegatee": (link["delegatee"], [capability["delegatee_seed_hex"]]),
            "kernel_key": (
                by_id(receipt["cases"])["allow_receipt"]["receipt"]["kernel_key"],
                [receipt["signing_key_seed_hex"]],
            ),
            "signing": (
                by_id(signing["json_cases"])["valid_canonical_json_message"]["public_key_hex"],
                [signing["signing_key_seed_hex"]],
            ),
        }
        for name, (public_hex, candidates) in shown.items():
            derived = {ed25519_public_from_seed(bytes.fromhex(s)).hex() for s in candidates}
            self.assertIn(public_hex, derived, name)

    def test_capability_cases_have_the_outcomes_they_are_chosen_for(self):
        cases = by_id(load("capability")["cases"])
        for case_id in ("valid_delegated_capability", "expired_capability", "broken_delegation_chain_signature"):
            case = cases[case_id]
            self.assertEqual(
                verify_capability(case["capability"], case["verify_at"]), case["expected"], case_id
            )
        self.assertEqual(cases["valid_delegated_capability"]["expected"]["time_status"], "valid")
        self.assertEqual(cases["expired_capability"]["expected"]["time_status"], "expired")
        broken = cases["broken_delegation_chain_signature"]["expected"]
        self.assertTrue(broken["signature_valid"])
        self.assertFalse(broken["delegation_chain_shape_valid"])

    def test_capability_body_is_the_token_without_its_signature(self):
        for case in load("capability")["cases"]:
            cap = case["capability"]
            body = {k: v for k, v in cap.items() if k != "signature"}
            self.assertEqual(rv.canonicalize(body), case["capability_body_canonical_json"], case["id"])

    def test_capability_signatures_cover_the_body_with_schema_added_and_not_the_body_alone(self):
        for case in load("capability")["cases"]:
            cap = case["capability"]
            signing_input = rv.capability_signing_input(cap)
            with_schema = json.loads(case["capability_body_canonical_json"])
            with_schema["schema"] = "chio.capability.v1"
            self.assertEqual(signing_input, rv.canonicalize(with_schema), case["id"])
            self.assertNotIn("algorithm", json.loads(signing_input))
            over_signing_input = verify_hex(cap["issuer"], signing_input.encode("ascii"), cap["signature"])
            over_body_alone = verify_hex(
                cap["issuer"], case["capability_body_canonical_json"].encode("ascii"), cap["signature"]
            )
            self.assertEqual(over_signing_input, case["expected"]["signature_valid"], case["id"])
            self.assertFalse(over_body_alone, case["id"])

    def test_the_signing_input_leaves_out_the_algorithm_member(self):
        token = {"id": "x", "algorithm": "ed25519", "signature": "00", "scope": {}}
        self.assertEqual(
            rv.capability_signing_input(token), '{"id":"x","schema":"chio.capability.v1","scope":{}}'
        )
        # A token that carries schema keeps its own value.
        token["schema"] = "chio.capability.v1"
        self.assertEqual(
            rv.capability_signing_input(token), '{"id":"x","schema":"chio.capability.v1","scope":{}}'
        )

    def test_receipt_signing_input_wraps_the_body_and_its_content_addressed_id(self):
        for case in load("receipt")["cases"]:
            receipt = case["receipt"]
            if not case["expected"]["receipt_id_valid"]:
                continue
            signing_input = rv.receipt_signing_input(receipt)
            members = json.loads(signing_input)
            self.assertEqual(sorted(members), ["body", "id"], case["id"])
            self.assertEqual(
                hashlib.sha256(rv.canonical_bytes(members["body"])).hexdigest(), members["id"], case["id"]
            )
            over_signing_input = verify_hex(
                receipt["kernel_key"], signing_input.encode("ascii"), receipt["signature"]
            )
            over_body = verify_hex(
                receipt["kernel_key"], case["receipt_body_canonical_json"].encode("ascii"), receipt["signature"]
            )
            self.assertFalse(over_body, case["id"])
            if case["expected"]["signature_valid"]:
                self.assertTrue(over_signing_input, case["id"])

    def test_receipt_cases_have_the_outcomes_they_are_chosen_for(self):
        cases = by_id(load("receipt")["cases"])
        for case_id in ("allow_receipt", "deny_receipt"):
            case = cases[case_id]
            checks = receipt_checks(case["receipt"])
            for name, value in checks.items():
                self.assertEqual(value, case["expected"][name], (case_id, name))
            self.assertEqual(
                rv.canonicalize({k: v for k, v in case["receipt"].items() if k != "signature"}),
                case["receipt_body_canonical_json"],
            )
        self.assertEqual(cases["allow_receipt"]["expected"]["decision"], "allow")
        self.assertEqual(cases["deny_receipt"]["expected"]["decision"], "deny")
        self.assertFalse(cases["allow_receipt"]["expected"]["signer_trusted"])

    def test_signing_cases_verify_or_fail_as_recorded(self):
        for case in load("signing")["json_cases"]:
            message = rv.canonical_bytes(rv.loads_strict(case["input_json"]))
            self.assertEqual(message.decode("utf-8"), case["canonical_json"], case["id"])
            self.assertEqual(
                verify_hex(case["public_key_hex"], message, case["signature_hex"]),
                case["expected_verify"],
                case["id"],
            )

    def test_hashing_cases_match_hashlib(self):
        for case in load("hashing")["cases"]:
            digest = hashlib.sha256(case["input_utf8"].encode("utf-8")).hexdigest()
            self.assertEqual(digest, case["sha256_hex"], case["id"])


# ---------------------------------------------------------------------------
# Appendix A.
# ---------------------------------------------------------------------------
class AppendixATests(unittest.TestCase):
    def setUp(self):
        self.intro, self.sections = parse_fragment(rendered()["appendix-a.md"].text)
        self.by_anchor = {s["anchor"]: s for s in self.sections}
        self.capability = by_id(load("capability")["cases"])["valid_delegated_capability"]
        self.receipt = by_id(load("receipt")["cases"])["allow_receipt"]

    def test_the_fragment_is_prose_then_three_anchored_subsections(self):
        self.assertTrue(self.intro and self.intro[0][0] == "p")
        self.assertEqual(
            [s["anchor"] for s in self.sections],
            ["example-capability", "example-frame", "example-receipt"],
        )
        self.assertTrue(all(item[0] == "p" for item in self.intro))

    def test_the_intro_names_both_source_cases(self):
        text = text_of(self.intro)
        for needle in (
            "`capability/v1.json` case `valid_delegated_capability`",
            "`receipt/v1.json` case `allow_receipt`",
            "{{RFC8792}}",
        ):
            self.assertIn(needle, text)

    def test_capability_example_is_the_valid_case_with_its_signing_input(self):
        items = self.by_anchor["example-capability"]["items"]
        match = PROVENANCE.search(items[0][1])
        self.assertEqual((match.group(1), match.group(2)), ("capability/v1.json", "valid_delegated_capability"))
        blocks = blocks_of(items)
        self.assertEqual([lang for lang, _ in blocks], ["json", "json"])
        self.assertIn("pretty-printed", items[0][1])
        cap = self.capability["capability"]
        self.assertEqual(json.loads(blocks[0][1]), cap)
        self.assertEqual(blocks[0][1], json.dumps(cap, indent=2))
        # The signing input is the corpus body with "schema" added, never the body alone.
        expected = json.loads(self.capability["capability_body_canonical_json"])
        expected["schema"] = "chio.capability.v1"
        self.assertEqual(blocks[1][1], rv.canonicalize(expected))
        self.assertNotEqual(blocks[1][1], self.capability["capability_body_canonical_json"])
        text = text_of(items)
        self.assertIn('`"schema":"chio.capability.v1"`', text)
        self.assertIn("`capability_body_canonical_json`", text)
        self.assertIn("signing input", text)

    def test_the_displayed_signing_input_verifies_against_the_issuer_key(self):
        """The bytes shown in the appendix are exactly what the vector signature covers."""
        items = self.by_anchor["example-capability"]["items"]
        cap = self.capability["capability"]
        signing = blocks_of(items)[1][1]
        members = json.loads(signing)
        self.assertEqual(members["issuer"], cap["issuer"])
        self.assertEqual(members["schema"], "chio.capability.v1")
        self.assertTrue(verify_hex(members["issuer"], signing.encode("ascii"), cap["signature"]))
        names = list(members)
        self.assertEqual(names[names.index("schema") - 1 : names.index("schema") + 2], ["issuer", "schema", "scope"])
        # One changed octet, or the body field as the corpus gives it, does not verify.
        self.assertFalse(verify_hex(members["issuer"], signing.replace("3", "4", 1).encode("ascii"), cap["signature"]))
        self.assertFalse(
            verify_hex(
                members["issuer"], self.capability["capability_body_canonical_json"].encode("ascii"), cap["signature"]
            )
        )

    def test_frame_example(self):
        items = self.by_anchor["example-frame"]["items"]
        blocks = blocks_of(items)
        self.assertEqual([lang for lang, _ in blocks], ["json", None, None])
        request_text, prefix_hex, head_hex = (content for _, content in blocks)
        request = json.loads(request_text)
        self.assertEqual(rv.canonicalize(request), request_text)
        self.assertEqual(
            sorted(request), ["capability_token", "id", "params", "server_id", "tool", "type"]
        )
        receipt = self.receipt["receipt"]
        self.assertEqual(request["type"], "tool_call_request")
        self.assertEqual(request["capability_token"], self.capability["capability"])
        self.assertEqual(request["server_id"], receipt["tool_server"])
        self.assertEqual(request["tool"], receipt["tool_name"])
        self.assertEqual(request["params"], receipt["action"]["parameters"])
        payload = request_text.encode("utf-8")
        self.assertEqual(prefix_hex, len(payload).to_bytes(4, "big").hex())
        self.assertEqual(len(prefix_hex), 8)
        self.assertEqual(head_hex, payload[:32].hex())
        self.assertEqual(len(head_hex), 64)
        text = text_of(items)
        self.assertIn("illustrative", text)
        self.assertIn(str(len(payload)), text)
        self.assertIn("`" + payload[:32].decode("ascii") + "`", text)
        self.assertIn("`capability/v1.json` case `valid_delegated_capability`", text)
        self.assertIn("`receipt/v1.json` case `allow_receipt`", text)

    def test_receipt_example_is_the_allow_case_with_its_signing_input(self):
        items = self.by_anchor["example-receipt"]["items"]
        match = PROVENANCE.search(items[0][1])
        self.assertEqual((match.group(1), match.group(2)), ("receipt/v1.json", "allow_receipt"))
        blocks = blocks_of(items)
        receipt = self.receipt["receipt"]
        self.assertEqual([lang for lang, _ in blocks], ["json", "json"])
        self.assertEqual(blocks[0][1], json.dumps(receipt, indent=2))
        signing = blocks[1][1]
        members = json.loads(signing)
        self.assertEqual(sorted(members), ["body", "id"])
        self.assertEqual(rv.canonicalize(members), signing)
        self.assertEqual(members["id"], receipt["id"])
        self.assertEqual(members["body"], {k: v for k, v in receipt.items() if k not in ("id", "signature")})
        text = text_of(items)
        self.assertIn("pretty-printed", text)
        self.assertIn("`cap-bindings-001`", text)
        self.assertIn("`receipt_body_canonical_json`", text)
        self.assertEqual(receipt["capability_id"], "cap-bindings-001")
        self.assertNotEqual(receipt["capability_id"], self.capability["capability"]["id"])

    def test_the_displayed_receipt_signing_input_verifies_against_the_kernel_key(self):
        items = self.by_anchor["example-receipt"]["items"]
        receipt = self.receipt["receipt"]
        signing = blocks_of(items)[1][1]
        members = json.loads(signing)
        self.assertEqual(members["body"]["kernel_key"], receipt["kernel_key"])
        self.assertTrue(verify_hex(receipt["kernel_key"], signing.encode("ascii"), receipt["signature"]))
        self.assertEqual(hashlib.sha256(rv.canonical_bytes(members["body"])).hexdigest(), members["id"])
        self.assertFalse(
            verify_hex(
                receipt["kernel_key"], self.receipt["receipt_body_canonical_json"].encode("ascii"), receipt["signature"]
            )
        )

    def test_the_receipt_id_and_parameter_hash_claims_hold(self):
        receipt = self.receipt["receipt"]
        checks = receipt_checks(receipt)
        self.assertEqual(checks, {"receipt_id_valid": True, "signature_valid": True, "parameter_hash_valid": True})
        text = text_of(self.by_anchor["example-receipt"]["items"])
        for needle in ("`parameter_hash`", "`parameters`", "`id`", "`signature`", "`body`", "`kernel_key`"):
            self.assertIn(needle, text)


# ---------------------------------------------------------------------------
# Appendix B.
# ---------------------------------------------------------------------------
class AppendixBTests(unittest.TestCase):
    def setUp(self):
        self.intro, self.sections = parse_fragment(rendered()["appendix-b.md"].text)
        self.by_anchor = {s["anchor"]: s for s in self.sections}

    def section_groups(self, anchor, file):
        found = groups(self.by_anchor[anchor])
        for group in found:
            self.assertEqual(group["file"], file)
        return found

    def test_the_fragment_is_prose_then_five_anchored_subsections(self):
        self.assertEqual(
            [s["anchor"] for s in self.sections],
            [
                "vectors-canonical",
                "vectors-hashing",
                "vectors-signing",
                "vectors-capability",
                "vectors-receipt",
            ],
        )
        self.assertTrue(self.intro and all(item[0] == "p" for item in self.intro))
        text = text_of(self.intro)
        for name in ("canonical", "hashing", "signing", "capability", "receipt"):
            self.assertIn("`%s/v1.json`" % name, text)
        self.assertIn("test keys", text)
        self.assertIn("{{RFC8792}}", text)

    def test_case_counts_follow_the_brief(self):
        counts = {
            anchor: len(groups(self.by_anchor[anchor]))
            for anchor in self.by_anchor
        }
        self.assertEqual(
            counts,
            {
                "vectors-canonical": 4,
                "vectors-hashing": 3,
                "vectors-signing": 2,
                "vectors-capability": 3,
                "vectors-receipt": 2,
            },
        )

    def test_canonical_cases(self):
        cases = by_id(load("canonical")["cases"])
        found = self.section_groups("vectors-canonical", "canonical/v1.json")
        self.assertEqual(
            [g["id"] for g in found],
            ["object_key_sorting", "utf16_key_ordering", "nested_structures", "number_formatting"],
        )
        for group in found:
            case = cases[group["id"]]
            blocks = blocks_of(group["items"])
            self.assertEqual(len(blocks), 2, group["id"])
            self.assertEqual(blocks[0], ("json", case["input_json"]), group["id"])
            if case["canonical_json"].isascii():
                self.assertEqual(blocks[1], ("json", case["canonical_json"]), group["id"])
            else:
                self.assertEqual(
                    blocks[1], (None, octets(case["canonical_json"].encode("utf-8"))), group["id"]
                )
        self.assertFalse(cases["utf16_key_ordering"]["canonical_json"].isascii())
        # The four cases cover key ordering, Unicode, nesting, and numbers.
        self.assertTrue(contains_float(rv.loads_strict(cases["number_formatting"]["input_json"])))

    def test_hashing_cases(self):
        cases = by_id(load("hashing")["cases"])
        found = self.section_groups("vectors-hashing", "hashing/v1.json")
        self.assertEqual(
            [g["id"] for g in found], ["abc_lowercase", "unicode_utf8", "json_canonical_form"]
        )
        for group in found:
            case = cases[group["id"]]
            blocks = blocks_of(group["items"])
            self.assertEqual(len(blocks), 2, group["id"])
            (input_lang, shown_input), (digest_lang, digest) = blocks
            if input_lang == "json":
                self.assertEqual(shown_input, case["input_utf8"], group["id"])
            else:
                self.assertIsNone(input_lang)
                self.assertEqual(shown_input, octets(case["input_utf8"].encode("utf-8")), group["id"])
            self.assertIsNone(digest_lang)
            self.assertEqual(digest, case["sha256_hex"], group["id"])
            self.assertEqual(len(digest), 64)

    def test_signing_cases(self):
        cases = by_id(load("signing")["json_cases"])
        found = self.section_groups("vectors-signing", "signing/v1.json")
        self.assertEqual(
            [g["id"] for g in found], ["valid_canonical_json_message", "tampered_canonical_json_message"]
        )
        for group in found:
            case = cases[group["id"]]
            blocks = blocks_of(group["items"])
            self.assertEqual(
                blocks,
                [
                    ("json", case["input_json"]),
                    ("json", case["canonical_json"]),
                    (None, case["public_key_hex"]),
                    (None, case["signature_hex"]),
                ],
                group["id"],
            )
            text = text_of(group["items"])
            self.assertIn("succeed" if case["expected_verify"] else "fail", text)
            # The shown message, key, and signature give the recorded outcome.
            self.assertEqual(
                verify_hex(blocks[2][1], blocks[1][1].encode("ascii"), blocks[3][1]),
                case["expected_verify"],
            )
        self.assertTrue(cases["valid_canonical_json_message"]["expected_verify"])
        self.assertFalse(cases["tampered_canonical_json_message"]["expected_verify"])

    def test_capability_cases(self):
        cases = by_id(load("capability")["cases"])
        found = self.section_groups("vectors-capability", "capability/v1.json")
        self.assertEqual(
            [g["id"] for g in found],
            ["valid_delegated_capability", "expired_capability", "broken_delegation_chain_signature"],
        )
        for group in found:
            case = cases[group["id"]]
            blocks = blocks_of(group["items"])
            self.assertEqual([lang for lang, _ in blocks], ["json", None, "json"], group["id"])
            signing_text, signature, expected_text = (content for _, content in blocks)
            expected = json.loads(expected_text)
            self.assertEqual(expected, case["expected"], group["id"])
            self.assertEqual(expected_text, json.dumps(case["expected"], indent=2), group["id"])
            self.assertEqual(signature, case["capability"]["signature"], group["id"])
            self.assertIn(str(case["verify_at"]), text_of(group["items"]), group["id"])
            # The signing input is the corpus body with schema added, and the token is
            # the body, without schema, plus the signature.
            members = json.loads(signing_text)
            self.assertEqual(rv.canonicalize(members), signing_text, group["id"])
            self.assertEqual(members.pop("schema"), "chio.capability.v1", group["id"])
            self.assertEqual(rv.canonicalize(members), case["capability_body_canonical_json"], group["id"])
            token = dict(members, signature=signature)
            self.assertEqual(token, case["capability"], group["id"])
            # The shown bytes verify under the shown issuer key, or not, as the result says.
            shown_issuer = json.loads(signing_text)["issuer"]
            self.assertEqual(
                verify_hex(shown_issuer, signing_text.encode("ascii"), signature),
                expected["signature_valid"],
                group["id"],
            )
            self.assertEqual(verify_capability(token, case["verify_at"]), expected, group["id"])

    def test_capability_prose_matches_each_outcome(self):
        found = self.section_groups("vectors-capability", "capability/v1.json")
        cases = by_id(load("capability")["cases"])
        valid, expired, broken = (text_of(g["items"]) for g in found)
        self.assertIn(str(cases["expired_capability"]["capability"]["expires_at"]), expired)
        self.assertIn("expired", expired)
        self.assertIn("delegation link", broken)
        self.assertIn("does not", broken)
        self.assertIn("delegation link", valid)
        self.assertIn('`"schema":"chio.capability.v1"`', text_of(self.by_anchor["vectors-capability"]["items"]))

    def test_receipt_cases(self):
        cases = by_id(load("receipt")["cases"])
        found = self.section_groups("vectors-receipt", "receipt/v1.json")
        self.assertEqual([g["id"] for g in found], ["allow_receipt", "deny_receipt"])
        for group in found:
            case = cases[group["id"]]
            blocks = blocks_of(group["items"])
            self.assertEqual([lang for lang, _ in blocks], ["json", None, "json"], group["id"])
            signing_text, signature, expected_text = (content for _, content in blocks)
            expected = json.loads(expected_text)
            self.assertEqual(expected_text, json.dumps(case["expected"], indent=2), group["id"])
            self.assertEqual(expected, case["expected"], group["id"])
            self.assertEqual(signature, case["receipt"]["signature"], group["id"])
            members = json.loads(signing_text)
            self.assertEqual(sorted(members), ["body", "id"], group["id"])
            self.assertEqual(rv.canonicalize(members), signing_text, group["id"])
            receipt = dict(members["body"], id=members["id"], signature=signature)
            self.assertEqual(receipt, case["receipt"], group["id"])
            self.assertEqual(
                rv.canonicalize({k: v for k, v in receipt.items() if k != "signature"}),
                case["receipt_body_canonical_json"],
                group["id"],
            )
            checks = receipt_checks(receipt)
            for name, value in checks.items():
                self.assertEqual(value, expected[name], (group["id"], name))
            self.assertEqual(
                verify_hex(members["body"]["kernel_key"], signing_text.encode("ascii"), signature),
                expected["signature_valid"],
                group["id"],
            )
            self.assertIn("no trusted signers", text_of(group["items"]))
        self.assertIn("allow", text_of(found[0]["items"]))
        self.assertIn("deny", text_of(found[1]["items"]))
        lead = text_of(self.by_anchor["vectors-receipt"]["items"][:1])
        self.assertIn("signing input", lead)
        self.assertIn("`receipt_body_canonical_json`", lead)


# ---------------------------------------------------------------------------
# Form of both fragments.
# ---------------------------------------------------------------------------
RISKY_LINE_START = re.compile(r"^(?:[#>|+*=~-]|\d+[.)]\s|\{:|\{#|\[)")
XREF = re.compile(r"\{\{([A-Za-z0-9._-]+)\}\}")
CODE_SPAN = re.compile(r"`[^`]*`")


def draft_anchors_and_references():
    text = DRAFT.read_text(encoding="utf-8")
    anchors = set(re.findall(r"\{#([A-Za-z0-9._-]+)\}", text))
    front = text.split("\n--- abstract", 1)[0]
    references = set(re.findall(r"^  ([A-Za-z0-9._-]+):", front, flags=re.M))
    return anchors, references


class FragmentFormTests(unittest.TestCase):
    def test_fragments_are_ascii_with_no_em_dash_tab_or_trailing_space(self):
        for name, fragment in rendered().items():
            text = fragment.text
            self.assertTrue(text.isascii(), name)
            self.assertNotIn("\U00002014", text)
            self.assertNotIn("\t", text)
            self.assertTrue(text.endswith("~~~\n") or text.endswith(".\n"), name)
            self.assertFalse(text.endswith("\n\n"), name)
            for number, line in enumerate(text.split("\n"), 1):
                self.assertEqual(line, line.rstrip(), (name, number))

    def test_code_lines_fit_69_columns_and_prose_lines_fit_72(self):
        for name, fragment in rendered().items():
            inside = False
            for number, line in enumerate(fragment.text.split("\n"), 1):
                if FENCE.match(line) and not inside:
                    inside = True
                    continue
                if line == "~~~" and inside:
                    inside = False
                    continue
                limit = 69 if inside else 72
                self.assertLessEqual(len(line), limit, (name, number, line))

    def test_every_folded_block_has_the_header_and_unfolds_to_its_source(self):
        total = 0
        for name, fragment in rendered().items():
            _, sections = parse_fragment(fragment.text)
            shown = [item for s in sections for item in s["items"] if item[0] == "b"]
            self.assertEqual(len(shown), len(fragment.blocks), name)
            for item, block in zip(shown, fragment.blocks):
                folded = item[2]
                self.assertEqual(block.lang, item[1])
                self.assertEqual(rv.unfold(folded), block.source, name)
                lines = folded.split("\n")
                long_source = any(len(x) > 69 for x in block.source.split("\n"))
                self.assertEqual(lines[0] == rv.fold_header(), long_source, (name, lines[0]))
                if long_source:
                    total += 1
                    self.assertEqual(lines[1], "")
                    self.assertTrue(any(x.endswith("\\") for x in lines))
                else:
                    self.assertEqual(folded, block.source)
        self.assertGreater(total, 10)

    def test_blocks_carry_the_languages_the_brief_allows(self):
        for fragment in rendered().values():
            for block in fragment.blocks:
                self.assertIn(block.lang, ("json", None))

    def test_prose_is_safe_for_kramdown(self):
        for name, fragment in rendered().items():
            inside = False
            for number, line in enumerate(fragment.text.split("\n"), 1):
                if FENCE.match(line) and not inside:
                    inside = True
                    continue
                if line == "~~~" and inside:
                    inside = False
                    continue
                if line == rv.KEEP_WITH_NEXT:
                    self.assertGreater(number, 1)
                    self.assertNotEqual(fragment.text.split("\n")[number - 2], "")
                    continue
                if inside or not line or HEADING.match(line):
                    continue
                self.assertIsNone(RISKY_LINE_START.match(line), (name, number, line))
                for span in CODE_SPAN.findall(line):
                    self.assertNotRegex(span, r"\s", (name, number, span))

    def test_headings_are_short_and_anchored(self):
        for name, fragment in rendered().items():
            _, sections = parse_fragment(fragment.text)
            self.assertGreaterEqual(len(sections), 3)
            for section in sections:
                self.assertLessEqual(len(section["title"]), 40)
                self.assertRegex(section["anchor"], r"^(example|vectors)-[a-z]+$")

    def test_cross_references_resolve_in_the_draft(self):
        anchors, references = draft_anchors_and_references()
        own = set()
        for fragment in rendered().values():
            own.update(re.findall(r"\{#([a-z0-9-]+)\}", fragment.text))
        used = set()
        for fragment in rendered().values():
            used.update(XREF.findall(fragment.text))
        self.assertTrue(used)
        for name in used:
            self.assertTrue(name in anchors or name in references or name in own, name)

    def test_the_draft_includes_both_fragments(self):
        text = DRAFT.read_text(encoding="utf-8")
        self.assertIn("{::include generated/appendix-a.md}", text)
        self.assertIn("{::include generated/appendix-b.md}", text)

    def test_the_repository_path_rules_of_the_draft_hold(self):
        for name, fragment in rendered().items():
            self.assertIsNone(re.search(r"crates/|\.rs\b|W1\.|phase [0-9]", fragment.text), name)
            self.assertNotIn("Arc", fragment.text)

    def test_rendering_is_deterministic(self):
        first = {name: f.text for name, f in rv.render_all(VECTORS).items()}
        second = {name: f.text for name, f in rv.render_all(VECTORS).items()}
        self.assertEqual(first, second)
        self.assertEqual(first, {name: f.text for name, f in rendered().items()})


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------
def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, timeout=120
    )


class CommandLineTests(unittest.TestCase):
    def test_write_then_check_passes_and_leaves_the_files_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "generated"
            result = run_cli("--vectors", str(VECTORS), "--out", str(out))
            self.assertEqual(result.returncode, 0, result.stderr)
            names = sorted(p.name for p in out.iterdir())
            self.assertEqual(names, ["appendix-a.md", "appendix-b.md"])
            before = {p.name: p.read_bytes() for p in out.iterdir()}
            for name, fragment in rendered().items():
                self.assertEqual(before[name], fragment.text.encode("ascii"))
            result = run_cli("--vectors", str(VECTORS), "--out", str(out), "--check")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(before, {p.name: p.read_bytes() for p in out.iterdir()})

    def test_check_fails_with_a_diff_when_a_fragment_differs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            self.assertEqual(run_cli("--vectors", str(VECTORS), "--out", str(out)).returncode, 0)
            path = out / "appendix-b.md"
            original = path.read_text(encoding="ascii")
            path.write_text(original.replace("1710000400", "1710000401", 1), encoding="ascii")
            result = run_cli("--vectors", str(VECTORS), "--out", str(out), "--check")
            self.assertEqual(result.returncode, 1)
            self.assertIn("appendix-b.md", result.stderr)
            self.assertIn("1710000401", result.stderr)
            self.assertEqual(path.read_text(encoding="ascii"), original.replace("1710000400", "1710000401", 1))

    def test_check_fails_when_a_fragment_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            self.assertEqual(run_cli("--vectors", str(VECTORS), "--out", str(out)).returncode, 0)
            (out / "appendix-a.md").unlink()
            result = run_cli("--vectors", str(VECTORS), "--out", str(out), "--check")
            self.assertEqual(result.returncode, 1)
            self.assertIn("appendix-a.md", result.stderr)
            self.assertFalse((out / "appendix-a.md").exists())

    def test_check_fails_when_a_folded_block_no_longer_unfolds_to_its_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            self.assertEqual(run_cli("--vectors", str(VECTORS), "--out", str(out)).returncode, 0)
            path = out / "appendix-a.md"
            text = path.read_text(encoding="ascii")
            # Drop the first fold marker: the file still parses, but the block differs.
            path.write_text(text.replace("\\\n", "\n", 1), encoding="ascii")
            result = run_cli("--vectors", str(VECTORS), "--out", str(out), "--check")
            self.assertEqual(result.returncode, 1)
            self.assertIn("unfold", result.stderr)

    def test_a_missing_corpus_is_an_error_and_not_a_difference(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_cli("--vectors", str(pathlib.Path(tmp) / "absent"), "--out", tmp)
            self.assertEqual(result.returncode, 2)
            self.assertIn("render_vectors", result.stderr)

    def test_a_corpus_that_no_longer_matches_its_manifest_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = pathlib.Path(tmp) / "vectors"
            for name in ("canonical", "hashing", "signing", "capability", "receipt"):
                (copy / name).mkdir(parents=True)
                (copy / name / "v1.json").write_bytes((VECTORS / name / "v1.json").read_bytes())
            (copy / "MANIFEST.sha256").write_bytes((VECTORS / "MANIFEST.sha256").read_bytes())
            ok = run_cli("--vectors", str(copy), "--out", str(pathlib.Path(tmp) / "a"))
            self.assertEqual(ok.returncode, 0, ok.stderr)
            target = copy / "hashing" / "v1.json"
            target.write_text(target.read_text(encoding="utf-8").replace("hello", "jello"), encoding="utf-8")
            bad = run_cli("--vectors", str(copy), "--out", str(pathlib.Path(tmp) / "b"))
            self.assertEqual(bad.returncode, 2)
            self.assertIn("MANIFEST.sha256", bad.stderr)

    def test_unknown_options_are_refused(self):
        self.assertEqual(run_cli("--vectors", str(VECTORS), "--out", "x", "--width", "72").returncode, 2)
        self.assertEqual(run_cli("--out", "x").returncode, 2)

    def test_the_committed_fragments_are_current(self):
        """The same gate as tools/check.sh applies to the generated files."""
        if not GENERATED.is_dir():
            self.skipTest("no generated directory")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = rv.main(["--vectors", str(VECTORS), "--out", str(GENERATED), "--check"])
        self.assertEqual(status, 0, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
