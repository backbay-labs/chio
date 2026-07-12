import Lake
open Lake DSL

require aeneas from "../vendor/aeneas"

package chio where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib Chio where
  srcDir := "."

@[default_target]
lean_lib FormalAeneas where
  srcDir := "."
  roots := #[`FormalAeneas.Types, `FormalAeneas.Funs]

@[default_target]
lean_lib FormalEconomy where
  srcDir := "."
  roots := #[`FormalEconomy.Types, `FormalEconomy.Funs]
