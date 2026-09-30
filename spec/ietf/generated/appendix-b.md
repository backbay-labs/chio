The cases in this appendix come from the files `canonical/v1.json`,
`hashing/v1.json`, `signing/v1.json`, `capability/v1.json`, and
`receipt/v1.json` of the Chio binding vector corpus, and all keys in
them are test keys derived from seeds that the corpus publishes. Lines
longer than 69 characters are folded as described in {{RFC8792}}, and
each folded block begins with the header line that document defines.

## Canonical JSON {#vectors-canonical}

Each case gives a JSON text and its canonical form, which {{encoding}}
defines.

The following case is `canonical/v1.json` case `object_key_sorting` from
the Chio binding vector corpus. Members are sorted by key. The input is:
{: keepWithNext="true"}

~~~ json
{"z":1,"a":2,"m":3}
~~~

The canonical form is:
{: keepWithNext="true"}

~~~ json
{"a":2,"m":3,"z":1}
~~~

The following case is `canonical/v1.json` case `utf16_key_ordering` from
the Chio binding vector corpus. Keys are compared as UTF-16 code units,
so the key U+10000, which the input writes as a surrogate pair, sorts
before the key U+E000, which is the reverse of their order as UTF-8
octets. The input is:
{: keepWithNext="true"}

~~~ json
{"\ue000":1,"\ud800\udc00":2}
~~~

The canonical form holds characters outside ASCII, so it is shown as its
18 octets, in hex:
{: keepWithNext="true"}

~~~
7b 22 f0 90 80 80 22 3a 32 2c 22 ee 80 80 22 3a 31 7d
~~~

The following case is `canonical/v1.json` case `nested_structures` from
the Chio binding vector corpus. Members are sorted at every level of
nesting, and the order of array elements is unchanged. The input is:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{"tool":"read","params":{"path":"/tmp/demo","flags":["read",\
"text"]},"enabled":true}
~~~

The canonical form is:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{"enabled":true,"params":{"flags":["read","text"],"path":\
"/tmp/demo"},"tool":"read"}
~~~

The following case is `canonical/v1.json` case `number_formatting` from
the Chio binding vector corpus. Numbers are written as ECMAScript writes
them: `1.0` becomes `1`, negative zero becomes `0`, and large and small
magnitudes use exponent forms such as `1e+21` and `1e-7`. The input is:
{: keepWithNext="true"}

~~~ json
{"whole":1.0,"small":1e-7,"big":1e21,"negative_zero":-0.0}
~~~

The canonical form is:
{: keepWithNext="true"}

~~~ json
{"big":1e+21,"negative_zero":0,"small":1e-7,"whole":1}
~~~

## SHA-256 Digests {#vectors-hashing}

Each case gives the octets of a UTF-8 string and their SHA-256 digest
{{FIPS180-4}}, written as 64 lowercase hex digits.

The following case is `hashing/v1.json` case `abc_lowercase` from the
Chio binding vector corpus. The input is the ASCII string `abc`, which
is three octets:
{: keepWithNext="true"}

~~~
61 62 63
~~~

The digest is:
{: keepWithNext="true"}

~~~
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
~~~

The following case is `hashing/v1.json` case `unicode_utf8` from the
Chio binding vector corpus. The input is the word `chio`, a space, and
the character U+1F510, which is 9 octets in UTF-8:
{: keepWithNext="true"}

~~~
63 68 69 6f 20 f0 9f 94 90
~~~

The digest is:
{: keepWithNext="true"}

~~~
5c57c7deea3998c13730797e592abe72cae55130e8da2923de6374b75b83101b
~~~

The following case is `hashing/v1.json` case `json_canonical_form` from
the Chio binding vector corpus. The input is a canonical JSON text:
{: keepWithNext="true"}

~~~ json
{"a":1,"b":[2,3]}
~~~

The digest is:
{: keepWithNext="true"}

~~~
efbd0040190fb0871831e606c581f8a66db79d8e2bb836745a70051306956070
~~~

## Ed25519 Signatures {#vectors-signing}

In each case the message is the canonical form of the JSON input, and
the signature is an Ed25519 signature {{RFC8032}} over the UTF-8 octets
of that message.

The following case is `signing/v1.json` case
`valid_canonical_json_message` from the Chio binding vector corpus. The
input is:
{: keepWithNext="true"}

~~~ json
{"z":1,"a":2}
~~~

Its canonical form, which is the message, is:
{: keepWithNext="true"}

~~~ json
{"a":2,"z":1}
~~~

The Ed25519 public key is:
{: keepWithNext="true"}

~~~
fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618
~~~

The signature is:
{: keepWithNext="true"}

~~~
=============== NOTE: '\' line wrapping per RFC 8792 ================

0b656434a9cf4f1d2f5cd0a2e008d69789251ecde8373781ee24d22f36abe53abf9f\
d51ee04df5c090143a5d49e14324a2d52f628472f02719bd405d2567590e
~~~

Verification is expected to succeed.

The following case is `signing/v1.json` case
`tampered_canonical_json_message` from the Chio binding vector corpus.
It reuses the signature of case `valid_canonical_json_message` for a
message whose value of `z` differs. The input is:
{: keepWithNext="true"}

~~~ json
{"z":2,"a":2}
~~~

Its canonical form, which is the message, is:
{: keepWithNext="true"}

~~~ json
{"a":2,"z":2}
~~~

The Ed25519 public key is:
{: keepWithNext="true"}

~~~
fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618
~~~

The signature is:
{: keepWithNext="true"}

~~~
=============== NOTE: '\' line wrapping per RFC 8792 ================

0b656434a9cf4f1d2f5cd0a2e008d69789251ecde8373781ee24d22f36abe53abf9f\
d51ee04df5c090143a5d49e14324a2d52f628472f02719bd405d2567590e
~~~

Verification is expected to fail.

## Capability Token Verification {#vectors-capability}

Each case gives the signing input of a token, the value of its
`signature` member, the Unix time at which the token is verified, and
the result that verification is expected to produce. The signing input
is the canonical form of the token without its `signature` member and
with the member `"schema":"chio.capability.v1"` added, as in
{{example-capability}}. The corpus omits the `schema` member from the
token itself, and its `capability_body_canonical_json` value is the
signing input without that member.

The following case is `capability/v1.json` case
`valid_delegated_capability` from the Chio binding vector corpus. Its
signature verifies, its delegation link verifies, and the verification
time falls within its validity period. Its signing input is:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{"delegation_chain":[{"capability_id":"cap-bindings-valid",\
"delegatee":\
"91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a",\
"delegator":\
"66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",\
"signature":"a4c297402d3bef255c8a9648215d9bb9c7fcbfb0a2e4009cfc62024\
59c10b2e4066de4ef60d4118f612993b6ceb2197095483e94c8a2ccc658ad7ef5b86\
5be00","timestamp":1710000250}],"expires_at":1710000800,"id":\
"cap-bindings-valid","issued_at":1710000200,"issuer":\
"66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",\
"schema":"chio.capability.v1","scope":{"grants":[{"constraints":\
[{"type":"path_prefix","value":"/workspace/"}],"max_invocations":3,\
"operations":["invoke","read_result"],"server_id":"srv-files",\
"tool_name":"file_read"}]},"subject":\
"0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d"}
~~~

The value of the `signature` member is:
{: keepWithNext="true"}

~~~
=============== NOTE: '\' line wrapping per RFC 8792 ================

a16f5a447da2a5dbd840e44c7c1a5093474e4a1b9826ae80ca85f197b18e8ad05607\
745ac9e0ff063db7b49ff4da637b630cf10d55c1ef1e64fb5c27d81ed505
~~~

Verification at Unix time 1710000400 is expected to produce:
{: keepWithNext="true"}

~~~ json
{
  "delegation_chain_shape_valid": true,
  "signature_valid": true,
  "time_status": "valid",
  "time_valid": true
}
~~~

The following case is `capability/v1.json` case `expired_capability`
from the Chio binding vector corpus. Its signature verifies, and it
expired at 1710000100, before the verification time. Its signing input
is:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{"expires_at":1710000100,"id":"cap-bindings-expired","issued_at":\
1710000000,"issuer":\
"66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",\
"schema":"chio.capability.v1","scope":{"grants":[{"constraints":\
[{"type":"path_prefix","value":"/workspace/"}],"max_invocations":3,\
"operations":["invoke","read_result"],"server_id":"srv-files",\
"tool_name":"file_read"}]},"subject":\
"0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d"}
~~~

The value of the `signature` member is:
{: keepWithNext="true"}

~~~
=============== NOTE: '\' line wrapping per RFC 8792 ================

d4f16e2dc56f829a047cf339e7139c0ceb859045f4854b746bdecf6901fb493a1088\
bab6456d2c39b38cc955f84041ebd22d8636bf4cfc45e838423b868de509
~~~

Verification at Unix time 1710000400 is expected to produce:
{: keepWithNext="true"}

~~~ json
{
  "delegation_chain_shape_valid": true,
  "signature_valid": true,
  "time_status": "expired",
  "time_valid": false
}
~~~

The following case is `capability/v1.json` case
`broken_delegation_chain_signature` from the Chio binding vector corpus.
Its signature verifies, and the signature of its delegation link does
not. Its signing input is:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{"delegation_chain":[{"capability_id":"cap-bindings-broken-chain",\
"delegatee":\
"91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a",\
"delegator":\
"66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",\
"signature":"e5031fd5c95e1cb79201c9750831e6604ee65fa451202f0ef540e9e\
30f7bc8e73ca877424e7ca3121db39cbb57e97827878a8656b077a7c084f9bfeeb84\
66f0e","timestamp":1710000301}],"expires_at":1710000800,"id":\
"cap-bindings-broken-chain","issued_at":1710000200,"issuer":\
"66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",\
"schema":"chio.capability.v1","scope":{"grants":[{"constraints":\
[{"type":"path_prefix","value":"/workspace/"}],"max_invocations":3,\
"operations":["invoke","read_result"],"server_id":"srv-files",\
"tool_name":"file_read"}]},"subject":\
"0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d"}
~~~

The value of the `signature` member is:
{: keepWithNext="true"}

~~~
=============== NOTE: '\' line wrapping per RFC 8792 ================

76466629cbe01ac3915bb67af0ff4fa591aec42d8a8f72e7c36731b7b1596cfb39e3\
a82dfc467dd2ed61c7ba7a5e728016d82b1702cbac5b8cc94719b99d0c08
~~~

Verification at Unix time 1710000400 is expected to produce:
{: keepWithNext="true"}

~~~ json
{
  "delegation_chain_shape_valid": false,
  "signature_valid": true,
  "time_status": "valid",
  "time_valid": true
}
~~~

## Receipt Verification {#vectors-receipt}

Each case gives the signing input of a receipt, the value of its
`signature` member, and the result that verification is expected to
produce. The signing input is the canonical form of a JSON object with
two members: `body`, which is the receipt without its `id` and
`signature` members, and `id`, which is the SHA-256 digest of the
canonical form of `body`, in lowercase hex, as in {{example-receipt}}.
The `receipt_body_canonical_json` value of each case is the canonical
form of the receipt without its `signature` member.

The following case is `receipt/v1.json` case `allow_receipt` from the
Chio binding vector corpus. It records an allow decision. Its signing
input is:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{"body":{"action":{"parameter_hash":\
"035350b0e6a021a4c924a149111944945e94d12f6d8a5e24e4461e7009ebf929",\
"parameters":{"mode":"read","path":"/workspace/docs/roadmap.md"}},\
"boundary_class":"prevent","capability_id":"cap-bindings-001",\
"content_hash":\
"4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93",\
"decision":{"verdict":"allow"},"evidence":[{"details":\
"path allowed","guard_name":"ForbiddenPathGuard","verdict":true},\
{"details":"no secrets detected","guard_name":"SecretLeakGuard",\
"verdict":true}],"kernel_key":\
"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",\
"metadata":{"surface":"bindings-vectors","version":1},"policy_hash":\
"policy-bindings-v1","receipt_kind":"mediated_decision",\
"redaction_mode":"none","timestamp":1710000200,"tool_name":\
"file_read","tool_origin":"caller_executed","tool_server":\
"srv-files","trust_level":"mediated"},"id":\
"c9909f733d5fb367922293f0167d06db715393be114f212096cf2866f29433ea"}
~~~

The value of the `signature` member is:
{: keepWithNext="true"}

~~~
=============== NOTE: '\' line wrapping per RFC 8792 ================

276a4c59dbc5e0c4fbd47beefa33515d207e8f516aca296afee2cb95a443bb18d310\
31cae0b69943e7a930be03b2e0a60156e5a26e732e888e32d4653d059f03
~~~

With no trusted signers configured, verification is expected to produce:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{
  "authorized": false,
  "boundary_class": "prevent",
  "decision": "allow",
  "ok": false,
  "parameter_hash_valid": true,
  "receipt_id_valid": true,
  "receipt_kind": "mediated_decision",
  "result": "Authorized",
  "signature_valid": true,
  "signer_key_hex": "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b9\
      2421eea691446d22c",
  "signer_trusted": false,
  "trust_level": "mediated"
}
~~~

The following case is `receipt/v1.json` case `deny_receipt` from the
Chio binding vector corpus. It records a deny decision by the guard
`ForbiddenPathGuard` for the path `/etc/shadow`. Its signing input is:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{"body":{"action":{"parameter_hash":\
"d6f55d803ff027795f4a4c43fd8f6d3119051f82b7e3e1a13b1713fd37ea7b09",\
"parameters":{"mode":"read","path":"/etc/shadow"}},"boundary_class":\
"prevent","capability_id":"cap-bindings-001","content_hash":\
"4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93",\
"decision":{"guard":"ForbiddenPathGuard","reason":\
"path is forbidden","verdict":"deny"},"evidence":[{"details":\
"path allowed","guard_name":"ForbiddenPathGuard","verdict":true},\
{"details":"no secrets detected","guard_name":"SecretLeakGuard",\
"verdict":true}],"kernel_key":\
"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",\
"metadata":{"surface":"bindings-vectors","version":1},"policy_hash":\
"policy-bindings-v1","receipt_kind":"mediated_decision",\
"redaction_mode":"none","timestamp":1710000200,"tool_name":\
"file_read","tool_origin":"caller_executed","tool_server":\
"srv-files","trust_level":"mediated"},"id":\
"56d5644db5c53d0bb837bf615a60e541724858757aee1b8259a25816b75bb682"}
~~~

The value of the `signature` member is:
{: keepWithNext="true"}

~~~
=============== NOTE: '\' line wrapping per RFC 8792 ================

e3778cd741746bf1295ed45d5ffa4d311dd7076d4e8d7c009bdf3283e88e693cc9cd\
19bb07d2f65d8306e04d1c58bdcbc1753d79af4a7c2234758b5dbf8a1c06
~~~

With no trusted signers configured, verification is expected to produce:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{
  "authorized": false,
  "boundary_class": "prevent",
  "decision": "deny",
  "ok": false,
  "parameter_hash_valid": true,
  "receipt_id_valid": true,
  "receipt_kind": "mediated_decision",
  "result": "Denied",
  "signature_valid": true,
  "signer_key_hex": "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b9\
      2421eea691446d22c",
  "signer_trusted": false,
  "trust_level": "mediated"
}
~~~
