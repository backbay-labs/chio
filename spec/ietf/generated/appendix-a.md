The examples in this appendix are built from two cases of the Chio
binding vector corpus, `capability/v1.json` case
`valid_delegated_capability` and `receipt/v1.json` case `allow_receipt`,
so every key, hash, and signature in them is exact. Lines longer than 69
characters are folded as described in {{RFC8792}}, and each folded block
begins with the header line that document defines.

## Capability Token {#example-capability}

The following case is `capability/v1.json` case
`valid_delegated_capability` from the Chio binding vector corpus. It is
a token with one delegation link and one tool grant, pretty-printed here
for reading. The corpus omits the `schema` member from its tokens.
Capability tokens are defined in {{capabilities}}.

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{
  "delegation_chain": [
    {
      "capability_id": "cap-bindings-valid",
      "delegatee": "91a28a0b74381593a4d9469579208926afc8ad82c8839b76\
          44359b9eba9a4b3a",
      "delegator": "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d\
          98b39fb6810c473a",
      "signature": "a4c297402d3bef255c8a9648215d9bb9c7fcbfb0a2e4009c\
          fc6202459c10b2e4066de4ef60d4118f612993b6ceb2197095483e94c8\
          a2ccc658ad7ef5b865be00",
      "timestamp": 1710000250
    }
  ],
  "expires_at": 1710000800,
  "id": "cap-bindings-valid",
  "issued_at": 1710000200,
  "issuer": "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb\
      6810c473a",
  "scope": {
    "grants": [
      {
        "constraints": [
          {
            "type": "path_prefix",
            "value": "/workspace/"
          }
        ],
        "max_invocations": 3,
        "operations": [
          "invoke",
          "read_result"
        ],
        "server_id": "srv-files",
        "tool_name": "file_read"
      }
    ]
  },
  "signature": "a16f5a447da2a5dbd840e44c7c1a5093474e4a1b9826ae80ca85\
      f197b18e8ad05607745ac9e0ff063db7b49ff4da637b630cf10d55c1ef1e64\
      fb5c27d81ed505",
  "subject": "0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da\
      8eb6e39f2d"
}
~~~

The signing input of the token is its canonical form without the
`signature` member and with the member `"schema":"chio.capability.v1"`
added, which sorts between `issuer` and `scope`. The
`capability_body_canonical_json` value of the case is the same text
without the `schema` member. The signing input is:
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

The `signature` member is an Ed25519 signature over these octets that
verifies under the key in `issuer`.

## Tool Call Request Frame {#example-frame}

The following request is built from `capability/v1.json` case
`valid_delegated_capability` and `receipt/v1.json` case `allow_receipt`
of the Chio binding vector corpus. Its `capability_token` is the token
of {{example-capability}}, and its `server_id`, `tool`, and `params` are
the `tool_server`, `tool_name`, and `action.parameters` members of the
receipt of {{example-receipt}}. Its `id` is illustrative. The request is
not a case of the corpus, and its canonical form is:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{"capability_token":{"delegation_chain":[{"capability_id":\
"cap-bindings-valid","delegatee":\
"91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a",\
"delegator":\
"66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",\
"signature":"a4c297402d3bef255c8a9648215d9bb9c7fcbfb0a2e4009cfc62024\
59c10b2e4066de4ef60d4118f612993b6ceb2197095483e94c8a2ccc658ad7ef5b86\
5be00","timestamp":1710000250}],"expires_at":1710000800,"id":\
"cap-bindings-valid","issued_at":1710000200,"issuer":\
"66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",\
"scope":{"grants":[{"constraints":[{"type":"path_prefix","value":\
"/workspace/"}],"max_invocations":3,"operations":["invoke",\
"read_result"],"server_id":"srv-files","tool_name":"file_read"}]},\
"signature":"a16f5a447da2a5dbd840e44c7c1a5093474e4a1b9826ae80ca85f19\
7b18e8ad05607745ac9e0ff063db7b49ff4da637b630cf10d55c1ef1e64fb5c27d81\
ed505","subject":\
"0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d"},\
"id":"req-001","params":{"mode":"read","path":\
"/workspace/docs/roadmap.md"},"server_id":"srv-files","tool":\
"file_read","type":"tool_call_request"}
~~~

In the native transport ({{native-transport}}), a message is sent as a
frame: a four-octet length in big-endian order, followed by the
canonical form as the payload. The payload here is 1111 octets long, so
the length prefix is:
{: keepWithNext="true"}

~~~
00000457
~~~

The first 32 octets of the payload are the ASCII text
`{"capability_token":{"delegation`. In hex they are:
{: keepWithNext="true"}

~~~
7b226361706162696c6974795f746f6b656e223a7b2264656c65676174696f6e
~~~

## Receipt {#example-receipt}

The following case is `receipt/v1.json` case `allow_receipt` from the
Chio binding vector corpus. It records an allow decision for a call with
the server, tool, and parameters of {{example-frame}}, and it is
pretty-printed here for reading. Its `capability_id` is
`cap-bindings-001`. The capability and receipt cases of the corpus are
independent, so that value is not the `id` of the token in
{{example-capability}}. Receipts are defined in {{receipts}}.

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{
  "action": {
    "parameter_hash": "035350b0e6a021a4c924a149111944945e94d12f6d8a5\
        e24e4461e7009ebf929",
    "parameters": {
      "mode": "read",
      "path": "/workspace/docs/roadmap.md"
    }
  },
  "boundary_class": "prevent",
  "capability_id": "cap-bindings-001",
  "content_hash": "4062edaf750fb8074e7e83e0c9028c94e32468a8b6f161477\
      4328ef045150f93",
  "decision": {
    "verdict": "allow"
  },
  "evidence": [
    {
      "details": "path allowed",
      "guard_name": "ForbiddenPathGuard",
      "verdict": true
    },
    {
      "details": "no secrets detected",
      "guard_name": "SecretLeakGuard",
      "verdict": true
    }
  ],
  "id": "c9909f733d5fb367922293f0167d06db715393be114f212096cf2866f29\
      433ea",
  "kernel_key": "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421\
      eea691446d22c",
  "metadata": {
    "surface": "bindings-vectors",
    "version": 1
  },
  "policy_hash": "policy-bindings-v1",
  "receipt_kind": "mediated_decision",
  "redaction_mode": "none",
  "signature": "276a4c59dbc5e0c4fbd47beefa33515d207e8f516aca296afee2\
      cb95a443bb18d31031cae0b69943e7a930be03b2e0a60156e5a26e732e888e\
      32d4653d059f03",
  "timestamp": 1710000200,
  "tool_name": "file_read",
  "tool_origin": "caller_executed",
  "tool_server": "srv-files",
  "trust_level": "mediated"
}
~~~

The signing input of the receipt is the canonical form of a JSON object
with two members: `body`, which is the receipt without its `id` and
`signature` members, and `id`, which is the SHA-256 digest of the
canonical form of `body`, in lowercase hex. The
`receipt_body_canonical_json` value of the case is the canonical form of
the receipt without its `signature` member. The signing input is:
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

The `signature` member is an Ed25519 signature over these octets that
verifies under the key in `kernel_key`. The `parameter_hash` member of
`action` is the SHA-256 digest of the canonical form of its `parameters`
member, in the same encoding.
