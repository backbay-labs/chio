#!/usr/bin/env python3
"""Render Appendices A and B of the Chio protocol Internet-Draft.

The draft includes two kramdown-rfc fragments verbatim:

    generated/appendix-a.md   examples: a capability token, a tool call
                              request frame that carries it, and a receipt
    generated/appendix-b.md   test vectors: canonical JSON, SHA-256 digests,
                              Ed25519 signatures, capability tokens, receipts

Both are built from the Chio binding vector corpus, so every key, hash, and
signature in them is exact. The script needs only the Python standard library.

    render_vectors.py --vectors DIR --out DIR           write the fragments
    render_vectors.py --vectors DIR --out DIR --check   compare, write nothing

--check renders in memory and compares the result with the files in --out. It
also unfolds every folded block, in the fresh render and in the files, and
compares the result with the source bytes of the block. It exits 1 on any
difference, and 2 when the corpus cannot be read or rendered.

Lines longer than 69 columns are folded with the single backslash strategy of
RFC 8792 section 7, under its header line. Canonical JSON follows RFC 8785 for
objects, arrays, strings, booleans, null, and numbers; integers are written in
full, as the corpus requires.
"""
from __future__ import annotations

import argparse
import bisect
import decimal
import difflib
import hashlib
import json
import pathlib
import re
import sys
import textwrap
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple


class RenderError(Exception):
    """The corpus cannot be read, or a selected case is not what the text says."""


class CanonicalizationError(ValueError):
    """A value has no RFC 8785 form."""


class FoldError(ValueError):
    """Text cannot be folded or unfolded under RFC 8792."""


# ---------------------------------------------------------------------------
# RFC 8785 canonical JSON.
# ---------------------------------------------------------------------------
_INT_MIN = -(2**63)
_INT_MAX = 2**64 - 1
_SHORT_ESCAPES = {
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
    '"': '\\"',
    "\\": "\\\\",
}


def loads_strict(text: str) -> Any:
    """Parse JSON, refusing duplicate object keys and non-finite numbers."""

    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("duplicate object key %r" % key)
            obj[key] = value
        return obj

    def constant(name):
        raise ValueError("%s is not a JSON value" % name)

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def _quote(text: str) -> str:
    """Serialize a string as RFC 8785 section 3.2.2.2 requires."""
    out = ['"']
    for char in text:
        escape = _SHORT_ESCAPES.get(char)
        if escape is not None:
            out.append(escape)
        elif char < " ":
            out.append("\\u%04x" % ord(char))
        elif "\ud800" <= char <= "\udfff":
            raise CanonicalizationError("a string holds a lone surrogate")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _utf16_key(key: str) -> bytes:
    """Sort key: the UTF-16 code units of the name, compared as unsigned integers."""
    try:
        return key.encode("utf-16-be")
    except UnicodeEncodeError as error:
        raise CanonicalizationError("an object key holds a lone surrogate") from error


def _format_float(value: float) -> str:
    """Number::toString of ECMAScript, as RFC 8785 section 3.2.2.3 requires."""
    if value != value or value in (float("inf"), float("-inf")):
        raise CanonicalizationError("NaN and Infinity have no JSON form")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # repr() yields the shortest digit string that reads back as the same
    # double, which is the digit string ECMAScript specifies.
    parts = decimal.Decimal(repr(abs(value))).as_tuple()
    full = "".join(map(str, parts.digits))
    digits = full.rstrip("0")
    exponent = parts.exponent + (len(full) - len(digits))
    k = len(digits)
    n = k + exponent  # the value is 0.DIGITS times 10 to the power n
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * -n + digits
    shift = n - 1
    suffix = "e" + ("+" if shift >= 0 else "-") + str(abs(shift))
    if k == 1:
        return sign + digits + suffix
    return sign + digits[0] + "." + digits[1:] + suffix


def _emit(value: Any, out: List[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_quote(value))
    elif isinstance(value, int):
        if not _INT_MIN <= value <= _INT_MAX:
            raise CanonicalizationError("integer %d does not fit in 64 bits" % value)
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_format_float(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _emit(item, out)
        out.append("]")
    elif isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise CanonicalizationError("object keys must be strings")
        out.append("{")
        for index, key in enumerate(sorted(value, key=_utf16_key)):
            if index:
                out.append(",")
            out.append(_quote(key))
            out.append(":")
            _emit(value[key], out)
        out.append("}")
    else:
        raise CanonicalizationError("cannot canonicalize a value of type %s" % type(value).__name__)


def canonicalize(value: Any) -> str:
    """Return the canonical JSON text of a parsed value."""
    out: List[str] = []
    _emit(value, out)
    return "".join(out)


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical JSON text of a parsed value as UTF-8 octets."""
    return canonicalize(value).encode("utf-8")


# ---------------------------------------------------------------------------
# RFC 8792 section 7: folding with the single backslash strategy.
# ---------------------------------------------------------------------------
FOLD_HEADER_TEXT = "NOTE: '\\' line wrapping per RFC 8792"
MAX_COLUMN = 69
_MIN_WIDTH = 40
_MIN_CONTENT = 20


def fold_header(width: int = MAX_COLUMN) -> str:
    """The header line of RFC 8792 section 7.1.1, centered in width columns."""
    padding = width - len(FOLD_HEADER_TEXT) - 2
    left = padding // 2
    return "=" * left + " " + FOLD_HEADER_TEXT + " " + "=" * (padding - left)


def _soft_breaks(line: str) -> List[int]:
    """Positions where a fold reads naturally: after a comma or a colon, and any spaces that follow."""
    positions: List[int] = []
    previous = ""
    for index, char in enumerate(line):
        if char != " ":
            if previous in (",", ":"):
                positions.append(index)
            previous = char
    return positions


def _soft_cut(
    line: str, soft: List[int], start: int, limit: int, width: int, continuation: int
) -> Optional[int]:
    """The last natural fold position up to limit, if the text after it then fits on one line."""
    at = bisect.bisect_right(soft, limit) - 1
    if at < 0 or soft[at] <= start:
        return None
    position = soft[at]
    following = soft[at + 1] if at + 1 < len(soft) else len(line)
    if following == len(line):
        fits = len(line) - position <= width - continuation  # the last piece needs no backslash
    else:
        fits = following - position <= width - 1 - continuation
    return position if fits else None


def _fold_line(line: str, width: int, extra_indent: int) -> List[str]:
    """Fold one line like a word wrapper: after a comma or colon, and inside only a long token."""
    if len(line) <= width:
        return [line]
    lead = len(line) - len(line.lstrip(" "))
    continuation = min(lead + extra_indent, max(0, width - 1 - _MIN_CONTENT))
    soft = _soft_breaks(line)
    pieces: List[str] = []
    start, prefix = 0, 0
    while prefix + len(line) - start > width:
        limit = start + width - 1 - prefix  # the last index at which a chunk may end
        cut = _soft_cut(line, soft, start, limit, width, continuation)
        if cut is None:
            # A token longer than a line is cut where the line ends. The text after
            # the fold must not start with a space, which unfolding would drop, and
            # a chunk must not end with a backslash, which would read as part of
            # the fold marker.
            cut = limit
            while cut > start and (line[cut] == " " or line[cut - 1] == "\\"):
                cut -= 1
            if cut == start:
                raise FoldError("no position allows a fold within %d columns" % width)
        pieces.append(" " * prefix + line[start:cut] + "\\")
        start, prefix = cut, continuation
    pieces.append(" " * prefix + line[start:])
    return pieces


def fold(text: str, width: int = MAX_COLUMN, extra_indent: int = 0) -> str:
    """Fold every line longer than width columns, as RFC 8792 section 7.2.1.

    Text whose lines all fit is returned unchanged. Otherwise the result starts
    with the header line and an empty line. A continuation line starts with the
    leading spaces of its source line plus extra_indent, which unfolding drops.
    """
    if width < _MIN_WIDTH:
        raise FoldError("the folding column must be at least %d" % _MIN_WIDTH)
    if "\t" in text:
        raise FoldError("the text contains a tab")
    lines = text.split("\n")
    if all(len(line) <= width for line in lines):
        return text
    if not text.isascii():
        raise FoldError("the text is not ASCII, and folding it would miscount columns")
    for line in lines:
        if line.endswith("\\"):
            raise FoldError("a line ends with a backslash, so unfolding would be ambiguous")
    folded = [fold_header(width), ""]
    for line in lines:
        folded.extend(_fold_line(line, width, extra_indent))
    return "\n".join(folded)


def unfold(text: str) -> str:
    """Undo fold(), as RFC 8792 section 7.2.2. Text without the header is unchanged."""
    lines = text.split("\n")
    if len(lines) < 2 or FOLD_HEADER_TEXT not in lines[0] or lines[1] != "":
        return text
    result: List[str] = []
    pending: Optional[str] = None
    for line in lines[2:]:
        if pending is not None:
            line = pending + line.lstrip(" ")
            pending = None
        if line.endswith("\\"):
            pending = line[:-1]
        else:
            result.append(line)
    if pending is not None:
        raise FoldError("the last line of the text ends with a fold marker")
    return "\n".join(result)


# ---------------------------------------------------------------------------
# The vector corpus.
# ---------------------------------------------------------------------------
VECTOR_FILES = ("canonical", "hashing", "signing", "capability", "receipt")
CORPUS_VERSION = 1


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RenderError(message)


class Corpus:
    """The five vector files that the appendices draw on."""

    def __init__(self, root: Any) -> None:
        self.root = pathlib.Path(root)
        _require(self.root.is_dir(), "%s is not a directory" % self.root)
        raw: Dict[str, bytes] = {}
        self.files: Dict[str, Any] = {}
        for name in VECTOR_FILES:
            path = self._path(name)
            try:
                raw[name] = path.read_bytes()
            except OSError as error:
                raise RenderError("cannot read %s: %s" % (path, error.strerror or error)) from error
            try:
                data = loads_strict(raw[name].decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                raise RenderError("%s is not valid JSON: %s" % (path, error)) from error
            _require(
                isinstance(data, dict) and data.get("version") == CORPUS_VERSION,
                "%s is not a corpus of version %d" % (path, CORPUS_VERSION),
            )
            self.files[name] = data
        self._check_manifest(raw)

    def _path(self, name: str) -> pathlib.Path:
        return self.root / name / "v1.json"

    def _check_manifest(self, raw: Dict[str, bytes]) -> None:
        """Refuse files that differ from the frozen corpus recorded in MANIFEST.sha256."""
        manifest = self.root / "MANIFEST.sha256"
        if not manifest.is_file():
            return
        recorded: Dict[str, str] = {}
        for line in manifest.read_text(encoding="utf-8").splitlines():
            fields = line.split(None, 1)
            if len(fields) == 2:
                recorded[fields[1].strip()] = fields[0]
        for name in VECTOR_FILES:
            suffix = "%s/v1.json" % name
            digests = [d for path, d in recorded.items() if path == suffix or path.endswith("/" + suffix)]
            _require(len(digests) == 1, "%s has no entry for %s" % (manifest, suffix))
            actual = hashlib.sha256(raw[name]).hexdigest()
            _require(
                actual == digests[0],
                "%s does not match %s (expected %s, found %s)"
                % (self._path(name), manifest.name, digests[0], actual),
            )

    def case(self, name: str, case_id: str, key: str = "cases") -> Dict[str, Any]:
        for case in self.files[name][key]:
            if case.get("id") == case_id:
                return case
        raise RenderError("%s/v1.json has no case %r" % (name, case_id))


# ---------------------------------------------------------------------------
# Fragment construction.
# ---------------------------------------------------------------------------
class Block(NamedTuple):
    lang: Optional[str]
    source: str
    folded: str


KEEP_WITH_NEXT = '{: keepWithNext="true"}'
_RISKY_LINE = re.compile(r"^(?:[#>|+*=~-]|\d+[.)]\s|\{:|\{#|\[)")
_CODE_SPAN = re.compile(r"`([^`]*)`")


def _wrap(text: str) -> str:
    """Wrap a paragraph at 72 columns, after checking that kramdown reads it as plain prose."""
    spans = _CODE_SPAN.findall(text)
    _require(text.count("`") == 2 * len(spans), "unbalanced backticks in: %s" % text[:60])
    for span in spans:
        # A code span holds no space, so line wrapping cannot split it.
        _require(span != "" and not re.search(r"\s", span), "a code span holds a space: %r" % span)
    wrapped = textwrap.fill(text, width=72, break_long_words=False, break_on_hyphens=False)
    for line in wrapped.split("\n"):
        _require(
            _RISKY_LINE.match(line) is None,
            "a wrapped line would start a Markdown construct: %r" % line,
        )
    return wrapped


class Fragment:
    """A kramdown-rfc fragment under construction."""

    def __init__(self) -> None:
        self._parts: List[str] = []
        self.blocks: List[Block] = []

    @property
    def text(self) -> str:
        return "\n\n".join(self._parts) + "\n"

    def para(self, text: str) -> None:
        """Add a paragraph. One that ends in a colon introduces a block and stays with it."""
        wrapped = _wrap(text)
        if text.endswith(":"):
            wrapped += "\n" + KEEP_WITH_NEXT
        self._parts.append(wrapped)

    def heading(self, title: str, anchor: str) -> None:
        self._parts.append("## %s {#%s}" % (title, anchor))

    def block(self, source: str, lang: Optional[str] = None, indent: int = 0) -> None:
        """Add a fenced block; indent is the extra indentation of folded lines."""
        _require(source.isascii(), "a block holds non-ASCII text: %r" % source[:40])
        try:
            folded = fold(source, extra_indent=indent)
        except FoldError as error:
            raise RenderError("cannot fold a block that starts %r: %s" % (source[:40], error)) from error
        self.blocks.append(Block(lang, source, folded))
        self._parts.append(("~~~" if lang is None else "~~~ " + lang) + "\n" + folded + "\n~~~")

    def verify(self) -> None:
        """Check that every block fits its columns and unfolds to its source."""
        for index, block in enumerate(self.blocks, 1):
            _require(
                all(len(line) <= MAX_COLUMN for line in block.folded.split("\n")),
                "block %d has a line longer than %d columns" % (index, MAX_COLUMN),
            )
            try:
                unfolded = unfold(block.folded)
            except FoldError as error:
                raise RenderError("block %d does not unfold: %s" % (index, error)) from error
            _require(unfolded == block.source, "block %d does not unfold to its source bytes" % index)


def case_ref(name: str, case_id: str) -> str:
    return "`%s/v1.json` case `%s`" % (name, case_id)


def provenance(name: str, case_id: str) -> str:
    return "The following case is %s from the Chio binding vector corpus." % case_ref(name, case_id)


def pretty(value: Any) -> str:
    return json.dumps(value, indent=2)


def octets(data: bytes) -> str:
    return " ".join("%02x" % byte for byte in data)


def without(obj: Dict[str, Any], *names: str) -> Dict[str, Any]:
    return {key: value for key, value in obj.items() if key not in names}


CAPABILITY_SCHEMA = "chio.capability.v1"
SCHEMA_MEMBER = '"schema":"%s"' % CAPABILITY_SCHEMA


def capability_signing_input(token: Dict[str, Any]) -> str:
    """The canonical JSON that a capability issuer signs.

    It is the token without its signature and algorithm members, with the schema
    member added when the token leaves it out, as every token of the corpus does.
    """
    body = without(token, "signature", "algorithm")
    body.setdefault("schema", CAPABILITY_SCHEMA)
    return canonicalize(body)


def receipt_body(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """The receipt without the members that its id and its signature do not cover."""
    return without(receipt, "id", "signature", "algorithm", "bbs_signature")


def receipt_signing_input(receipt: Dict[str, Any]) -> str:
    """The canonical JSON that a kernel signs: the body and its content-addressed id."""
    return canonicalize({"id": receipt["id"], "body": receipt_body(receipt)})


def check_capability_signing_input(case: Dict[str, Any]) -> str:
    """Return the signing input of a capability case after checking how it relates to the corpus."""
    signing_input = capability_signing_input(case["capability"])
    members = loads_strict(signing_input)
    _require(
        canonicalize(without(members, "schema")) == case["capability_body_canonical_json"],
        "the signing input of %s is not capability_body_canonical_json plus schema" % case["id"],
    )
    names = list(members)
    at = names.index("schema")
    _require(
        names[at - 1 : at + 2] == ["issuer", "schema", "scope"],
        "schema no longer sorts between issuer and scope in %s" % case["id"],
    )
    return signing_input


def check_receipt_signing_input(case: Dict[str, Any]) -> str:
    """Return the signing input of a receipt case after checking how it relates to the corpus."""
    receipt = case["receipt"]
    _require(
        canonicalize(without(receipt, "signature")) == case["receipt_body_canonical_json"],
        "the canonical form of %s differs from the corpus" % case["id"],
    )
    _require(
        hashlib.sha256(canonical_bytes(receipt_body(receipt))).hexdigest() == receipt["id"],
        "%s: id is not the digest of the canonical body" % case["id"],
    )
    return receipt_signing_input(receipt)


# ---------------------------------------------------------------------------
# Appendix A: examples.
# ---------------------------------------------------------------------------
CAPABILITY_OUTCOMES = {
    "valid": {
        "signature_valid": True,
        "delegation_chain_shape_valid": True,
        "time_valid": True,
        "time_status": "valid",
    },
    "expired": {
        "signature_valid": True,
        "delegation_chain_shape_valid": True,
        "time_valid": False,
        "time_status": "expired",
    },
    "broken_chain": {
        "signature_valid": True,
        "delegation_chain_shape_valid": False,
        "time_valid": True,
        "time_status": "valid",
    },
}
REQUEST_ID = "req-001"


def build_appendix_a(corpus: Corpus) -> Fragment:
    cap_id, rec_id = "valid_delegated_capability", "allow_receipt"
    cap_case = corpus.case("capability", cap_id)
    rec_case = corpus.case("receipt", rec_id)
    cap, rec = cap_case["capability"], rec_case["receipt"]
    _require(cap_case["expected"] == CAPABILITY_OUTCOMES["valid"], "%s is not a valid token" % cap_id)
    _require(
        len(cap.get("delegation_chain", [])) == 1 and len(cap["scope"]["grants"]) == 1,
        "%s no longer has one delegation link and one grant" % cap_id,
    )
    _require(rec_case["expected"]["decision"] == "allow", "%s is not an allow receipt" % rec_id)
    cap_signing = check_capability_signing_input(cap_case)
    rec_signing = check_receipt_signing_input(rec_case)
    _require(
        hashlib.sha256(canonical_bytes(rec["action"]["parameters"])).hexdigest()
        == rec["action"]["parameter_hash"],
        "%s: parameter_hash is not the digest of the canonical parameters" % rec_id,
    )

    request = {
        "type": "tool_call_request",
        "id": REQUEST_ID,
        "capability_token": cap,
        "server_id": rec["tool_server"],
        "tool": rec["tool_name"],
        "params": rec["action"]["parameters"],
    }
    request_text = canonicalize(request)
    payload = request_text.encode("utf-8")
    cap_ref, rec_ref = case_ref("capability", cap_id), case_ref("receipt", rec_id)

    f = Fragment()
    f.para(
        "The examples in this appendix are built from two cases of the Chio binding vector "
        "corpus, %s and %s, so every key, hash, and signature in them is exact. Lines longer "
        "than 69 characters are folded as described in {{RFC8792}}, and each folded block "
        "begins with the header line that document defines." % (cap_ref, rec_ref)
    )

    f.heading("Capability Token", "example-capability")
    f.para(
        "%s It is a token with one delegation link and one tool grant, pretty-printed here for "
        "reading. The corpus omits the `schema` member from its tokens. Capability tokens are "
        "defined in {{capabilities}}." % provenance("capability", cap_id)
    )
    f.block(pretty(cap), "json", indent=4)
    f.para(
        "The signing input of the token is its canonical form without the `signature` member and "
        "with the member `%s` added, which sorts between `issuer` and `scope`. The "
        "`capability_body_canonical_json` value of the case is the same text without the `schema` "
        "member. The signing input is:" % SCHEMA_MEMBER
    )
    f.block(cap_signing, "json")
    f.para(
        "The `signature` member is an Ed25519 signature over these octets that verifies under the "
        "key in `issuer`."
    )

    f.heading("Tool Call Request Frame", "example-frame")
    f.para(
        "The following request is built from %s and %s of the Chio binding vector corpus. Its "
        "`capability_token` is the token of {{example-capability}}, and its `server_id`, `tool`, "
        "and `params` are the `tool_server`, `tool_name`, and `action.parameters` members of the "
        "receipt of {{example-receipt}}. Its `id` is illustrative. The request is not a case of "
        "the corpus, and its canonical form is:" % (cap_ref, rec_ref)
    )
    f.block(request_text, "json")
    f.para(
        "In the native transport ({{native-transport}}), a message is sent as a frame: a "
        "four-octet length in big-endian order, followed by the canonical form as the payload. "
        "The payload here is %d octets long, so the length prefix is:" % len(payload)
    )
    f.block(len(payload).to_bytes(4, "big").hex())
    f.para(
        "The first 32 octets of the payload are the ASCII text `%s`. In hex they are:"
        % payload[:32].decode("ascii")
    )
    f.block(payload[:32].hex())

    f.heading("Receipt", "example-receipt")
    f.para(
        "%s It records an allow decision for a call with the server, tool, and parameters of "
        "{{example-frame}}, and it is pretty-printed here for reading. Its `capability_id` is "
        "`%s`. The capability and receipt cases of the corpus are independent, so that value is "
        "not the `id` of the token in {{example-capability}}. Receipts are defined in "
        "{{receipts}}." % (provenance("receipt", rec_id), rec["capability_id"])
    )
    f.block(pretty(rec), "json", indent=4)
    f.para(
        "The signing input of the receipt is the canonical form of a JSON object with two "
        "members: `body`, which is the receipt without its `id` and `signature` members, and "
        "`id`, which is the SHA-256 digest of the canonical form of `body`, in lowercase hex. The "
        "`receipt_body_canonical_json` value of the case is the canonical form of the receipt "
        "without its `signature` member. The signing input is:"
    )
    f.block(rec_signing, "json")
    f.para(
        "The `signature` member is an Ed25519 signature over these octets that verifies under the "
        "key in `kernel_key`. The `parameter_hash` member of `action` is the SHA-256 digest of the "
        "canonical form of its `parameters` member, in the same encoding."
    )
    return f


# ---------------------------------------------------------------------------
# Appendix B: test vectors.
# ---------------------------------------------------------------------------
def _canonical_case(f: Fragment, corpus: Corpus, case_id: str, what: str) -> None:
    case = corpus.case("canonical", case_id)
    _require(
        canonicalize(loads_strict(case["input_json"])) == case["canonical_json"],
        "the canonicalizer disagrees with canonical/v1.json case %s" % case_id,
    )
    f.para("%s %s The input is:" % (provenance("canonical", case_id), what))
    f.block(case["input_json"], "json")
    if case["canonical_json"].isascii():
        f.para("The canonical form is:")
        f.block(case["canonical_json"], "json")
    else:
        data = case["canonical_json"].encode("utf-8")
        f.para(
            "The canonical form holds characters outside ASCII, so it is shown as its %d octets, "
            "in hex:" % len(data)
        )
        f.block(octets(data))


def _signing_case(f: Fragment, case: Dict[str, Any], note: str = "") -> None:
    f.para("%s%s The input is:" % (provenance("signing", case["id"]), note))
    f.block(case["input_json"], "json")
    f.para("Its canonical form, which is the message, is:")
    f.block(case["canonical_json"], "json")
    f.para("The Ed25519 public key is:")
    f.block(case["public_key_hex"])
    f.para("The signature is:")
    f.block(case["signature_hex"])
    f.para("Verification is expected to %s." % ("succeed" if case["expected_verify"] else "fail"))


def _capability_case(f: Fragment, corpus: Corpus, case_id: str, outcome: str, what: str) -> None:
    case = corpus.case("capability", case_id)
    _require(
        case["expected"] == CAPABILITY_OUTCOMES[outcome],
        "capability/v1.json case %s no longer has the %s outcome" % (case_id, outcome),
    )
    f.para("%s %s Its signing input is:" % (provenance("capability", case_id), what))
    f.block(check_capability_signing_input(case), "json")
    f.para("The value of the `signature` member is:")
    f.block(case["capability"]["signature"])
    f.para("Verification at Unix time %d is expected to produce:" % case["verify_at"])
    f.block(pretty(case["expected"]), "json", indent=4)


def _receipt_case(f: Fragment, corpus: Corpus, case_id: str, what: str) -> None:
    case = corpus.case("receipt", case_id)
    f.para("%s %s Its signing input is:" % (provenance("receipt", case_id), what))
    f.block(check_receipt_signing_input(case), "json")
    f.para("The value of the `signature` member is:")
    f.block(case["receipt"]["signature"])
    f.para("With no trusted signers configured, verification is expected to produce:")
    f.block(pretty(case["expected"]), "json", indent=4)


def build_appendix_b(corpus: Corpus) -> Fragment:
    files = ["`%s/v1.json`" % name for name in VECTOR_FILES]
    f = Fragment()
    f.para(
        "The cases in this appendix come from the files %s, and %s of the Chio binding vector "
        "corpus, and all keys in them are test keys derived from seeds that the corpus publishes. "
        "Lines longer than 69 characters are folded as described in {{RFC8792}}, and each folded "
        "block begins with the header line that document defines." % (", ".join(files[:-1]), files[-1])
    )

    f.heading("Canonical JSON", "vectors-canonical")
    f.para("Each case gives a JSON text and its canonical form, which {{encoding}} defines.")
    _canonical_case(f, corpus, "object_key_sorting", "Members are sorted by key.")
    _canonical_case(
        f,
        corpus,
        "utf16_key_ordering",
        "Keys are compared as UTF-16 code units, so the key U+10000, which the input writes as "
        "a surrogate pair, sorts before the key U+E000, which is the reverse of their order as "
        "UTF-8 octets.",
    )
    _canonical_case(
        f,
        corpus,
        "nested_structures",
        "Members are sorted at every level of nesting, and the order of array elements is "
        "unchanged.",
    )
    _canonical_case(
        f,
        corpus,
        "number_formatting",
        "Numbers are written as ECMAScript writes them: `1.0` becomes `1`, negative zero becomes "
        "`0`, and large and small magnitudes use exponent forms such as `1e+21` and `1e-7`.",
    )

    f.heading("SHA-256 Digests", "vectors-hashing")
    f.para(
        "Each case gives the octets of a UTF-8 string and their SHA-256 digest {{FIPS180-4}}, "
        "written as 64 lowercase hex digits."
    )
    case = corpus.case("hashing", "abc_lowercase")
    _require(case["input_utf8"] == "abc", "hashing/v1.json case abc_lowercase changed")
    f.para(
        "%s The input is the ASCII string `abc`, which is three octets:"
        % provenance("hashing", case["id"])
    )
    f.block(octets(case["input_utf8"].encode("utf-8")))
    f.para("The digest is:")
    f.block(case["sha256_hex"])
    case = corpus.case("hashing", "unicode_utf8")
    _require(case["input_utf8"] == "chio \U0001f510", "hashing/v1.json case unicode_utf8 changed")
    data = case["input_utf8"].encode("utf-8")
    f.para(
        "%s The input is the word `chio`, a space, and the character U+1F510, which is %d octets "
        "in UTF-8:" % (provenance("hashing", case["id"]), len(data))
    )
    f.block(octets(data))
    f.para("The digest is:")
    f.block(case["sha256_hex"])
    case = corpus.case("hashing", "json_canonical_form")
    _require(
        canonicalize(loads_strict(case["input_utf8"])) == case["input_utf8"],
        "hashing/v1.json case json_canonical_form is not canonical JSON",
    )
    f.para("%s The input is a canonical JSON text:" % provenance("hashing", case["id"]))
    f.block(case["input_utf8"], "json")
    f.para("The digest is:")
    f.block(case["sha256_hex"])

    f.heading("Ed25519 Signatures", "vectors-signing")
    f.para(
        "In each case the message is the canonical form of the JSON input, and the signature is "
        "an Ed25519 signature {{RFC8032}} over the UTF-8 octets of that message."
    )
    valid = corpus.case("signing", "valid_canonical_json_message", "json_cases")
    tampered = corpus.case("signing", "tampered_canonical_json_message", "json_cases")
    for case in (valid, tampered):
        _require(
            canonicalize(loads_strict(case["input_json"])) == case["canonical_json"],
            "the canonicalizer disagrees with signing/v1.json case %s" % case["id"],
        )
    _require(valid["expected_verify"] is True, "signing/v1.json case valid_canonical_json_message changed")
    _require(
        tampered["expected_verify"] is False, "signing/v1.json case tampered_canonical_json_message changed"
    )
    _require(
        tampered["signature_hex"] == valid["signature_hex"]
        and tampered["public_key_hex"] == valid["public_key_hex"],
        "the tampered signing case no longer reuses the signature of the valid case",
    )
    _signing_case(f, valid)
    _signing_case(
        f,
        tampered,
        " It reuses the signature of case `%s` for a message whose value of `z` differs."
        % valid["id"],
    )

    f.heading("Capability Token Verification", "vectors-capability")
    f.para(
        "Each case gives the signing input of a token, the value of its `signature` member, the "
        "Unix time at which the token is verified, and the result that verification is expected "
        "to produce. The signing input is the canonical form of the token without its `signature` "
        "member and with the member `%s` added, as in {{example-capability}}. The "
        "corpus omits the `schema` member from the token itself, and its "
        "`capability_body_canonical_json` value is the signing input without that member."
        % SCHEMA_MEMBER
    )
    expired = corpus.case("capability", "expired_capability")
    _capability_case(
        f,
        corpus,
        "valid_delegated_capability",
        "valid",
        "Its signature verifies, its delegation link verifies, and the verification time falls "
        "within its validity period.",
    )
    _capability_case(
        f,
        corpus,
        "expired_capability",
        "expired",
        "Its signature verifies, and it expired at %d, before the verification time."
        % expired["capability"]["expires_at"],
    )
    _capability_case(
        f,
        corpus,
        "broken_delegation_chain_signature",
        "broken_chain",
        "Its signature verifies, and the signature of its delegation link does not.",
    )

    f.heading("Receipt Verification", "vectors-receipt")
    f.para(
        "Each case gives the signing input of a receipt, the value of its `signature` member, and "
        "the result that verification is expected to produce. The signing input is the canonical "
        "form of a JSON object with two members: `body`, which is the receipt without its `id` "
        "and `signature` members, and `id`, which is the SHA-256 digest of the canonical form of "
        "`body`, in lowercase hex, as in {{example-receipt}}. The `receipt_body_canonical_json` "
        "value of each case is the canonical form of the receipt without its `signature` member."
    )
    allow = corpus.case("receipt", "allow_receipt")
    deny = corpus.case("receipt", "deny_receipt")
    _require(allow["receipt"]["decision"] == {"verdict": "allow"}, "allow_receipt is not an allow")
    _require(deny["receipt"]["decision"]["verdict"] == "deny", "deny_receipt is not a deny")
    _receipt_case(f, corpus, "allow_receipt", "It records an allow decision.")
    _receipt_case(
        f,
        corpus,
        "deny_receipt",
        "It records a deny decision by the guard `%s` for the path `%s`."
        % (deny["receipt"]["decision"]["guard"], deny["receipt"]["action"]["parameters"]["path"]),
    )
    return f


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------
def render_all(vectors: Any) -> Dict[str, Fragment]:
    """Render both fragments from the corpus in the directory vectors."""
    corpus = Corpus(vectors)
    fragments = {"appendix-a.md": build_appendix_a(corpus), "appendix-b.md": build_appendix_b(corpus)}
    for fragment in fragments.values():
        fragment.verify()
    return fragments


_FENCE = re.compile(r"^~~~(?: (\S+))?$")


def extract_blocks(markdown: str) -> List[Tuple[Optional[str], str]]:
    """List the fenced blocks of a fragment as (language, content) pairs."""
    blocks: List[Tuple[Optional[str], str]] = []
    current: Optional[List[str]] = None
    lang: Optional[str] = None
    for line in markdown.split("\n"):
        if current is None:
            match = _FENCE.match(line)
            if match:
                current, lang = [], match.group(1)
        elif line == "~~~":
            blocks.append((lang, "\n".join(current)))
            current = None
        else:
            current.append(line)
    if current is not None:
        raise ValueError("a fenced block is not closed")
    return blocks


def _say(message: str) -> None:
    print("render_vectors: " + message, file=sys.stderr)


def check(fragments: Dict[str, Fragment], out: pathlib.Path) -> int:
    """Compare fresh fragments with the files in out. Return 1 on any difference."""
    status = 0
    for name, fragment in fragments.items():
        path = out / name
        try:
            committed = path.read_text(encoding="ascii")
        except FileNotFoundError:
            _say("%s is missing; run make vectors" % path)
            status = 1
            continue
        except (OSError, UnicodeDecodeError) as error:
            _say("cannot read %s: %s" % (path, error))
            status = 1
            continue
        if committed != fragment.text:
            status = 1
            _say("%s differs from a fresh render; run make vectors" % path)
            diff = difflib.unified_diff(
                committed.splitlines(),
                fragment.text.splitlines(),
                fromfile="%s (committed)" % path,
                tofile="%s (fresh)" % path,
                lineterm="",
            )
            for count, line in enumerate(diff):
                if count >= 60:
                    print("...", file=sys.stderr)
                    break
                print(line, file=sys.stderr)
        try:
            blocks = extract_blocks(committed)
        except ValueError as error:
            _say("%s: %s" % (path, error))
            status = 1
            continue
        if len(blocks) != len(fragment.blocks):
            _say("%s has %d blocks, and a fresh render has %d" % (path, len(blocks), len(fragment.blocks)))
            status = 1
            continue
        for index, ((lang, content), block) in enumerate(zip(blocks, fragment.blocks), 1):
            try:
                same = unfold(content) == block.source
            except FoldError as error:
                _say("block %d of %s does not unfold: %s" % (index, path, error))
                status = 1
                continue
            if not same:
                _say("block %d of %s does not unfold to its source bytes" % (index, path))
                status = 1
            elif lang != block.lang:
                _say("block %d of %s has the language %r, and a fresh render has %r" % (index, path, lang, block.lang))
                status = 1
    return status


def write(fragments: Dict[str, Fragment], out: pathlib.Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, fragment in fragments.items():
        with open(out / name, "w", encoding="ascii", newline="\n") as handle:
            handle.write(fragment.text)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="render_vectors.py",
        description="Render Appendices A and B of the Chio protocol draft from the binding vector corpus.",
    )
    parser.add_argument("--vectors", required=True, help="directory that holds the binding vector corpus")
    parser.add_argument("--out", required=True, help="directory for appendix-a.md and appendix-b.md")
    parser.add_argument(
        "--check", action="store_true", help="compare with the files in --out and write nothing"
    )
    args = parser.parse_args(argv)
    out = pathlib.Path(args.out)
    try:
        fragments = render_all(args.vectors)
        if args.check:
            return check(fragments, out)
        write(fragments, out)
    except RenderError as error:
        _say("error: %s" % error)
        return 2
    except OSError as error:
        _say("error: %s" % error)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
