import Lake
open Lake DSL

package chio where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib Chio where
  srcDir := "."
