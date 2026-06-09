# chio-core

`chio-core` defines the core Rust protocol surface for Chio: capabilities,
receipts, canonical JSON, signing helpers, Merkle utilities, and the shared
typed artifacts consumed by higher runtime layers.

Use `chio-core` when you need Chio protocol types or verification helpers without
embedding the full governed runtime. If you need request evaluation and receipt
signing, start with `chio-kernel`.
