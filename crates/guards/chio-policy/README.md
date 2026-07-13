# chio-policy

`chio-policy` is Chio's HushSpec policy layer. It parses, validates, merges,
evaluates, analyzes, and compiles policy documents into the runtime guard and
constraint surface used by the supported stack.

Use this crate when you are working on policy authoring, validation, or runtime
compilation instead of the lower-level guard implementations directly.

The `analyze` module exposes bounded rule relations and policy refinement
checks. The `chio policy analyze` command is the supported operator surface;
see [Policy Analysis](../../../docs/reference/POLICY_ANALYSIS.md).
