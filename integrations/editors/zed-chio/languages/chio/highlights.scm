; Tree-sitter highlight queries for Chio documents.
;
; Chio reuses tree-sitter-yaml so the queries are scoped to the
; constructs Chio cares about: capability/policy/guard keys,
; urn:chio:error:* references, and string/number literals.

(comment) @comment

((block_mapping_pair
  key: (flow_node) @keyword)
  (#match? @keyword "^(capability|capabilities|policy|guard|guards|manifest|scope|allow|deny|version)$"))

((block_mapping_pair
  key: (flow_node) @entity.name.tag))

((string_scalar) @constant.other.urn
  (#match? @constant.other.urn "urn:chio:error:[a-z0-9_:-]+"))

(string_scalar) @string

(integer_scalar) @number
(float_scalar) @number
(boolean_scalar) @constant.builtin
(null_scalar) @constant.builtin
