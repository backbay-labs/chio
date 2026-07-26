import Lean

open Lean

def moduleName (value : String) : Name :=
  value.splitOn "." |>.foldl (fun name component => name.str component) .anonymous

def splitArguments (args : List String) : Except String (List String × List String) :=
  let rec split (roots : List String) : List String → Except String (List String × List String)
    | [] => .error "expected root imports, --, then audited modules"
    | "--" :: modules =>
        if roots.isEmpty then
          .error "at least one root import is required"
        else if modules.isEmpty then
          .error "at least one audited module is required"
        else
          .ok (roots.reverse, modules)
    | value :: rest => split (value :: roots) rest
  split [] args

def main (args : List String) : IO UInt32 := do
  let (rootValues, auditedValues) ←
    match splitArguments args with
    | .ok values => pure values
    | .error message => throw (IO.userError message)
  let imports := rootValues.toArray.map fun value => { module := moduleName value }
  let env ← importModules imports {} 0
  for value in auditedValues do
    unless env.getModuleIdx? (moduleName value) |>.isSome do
      throw (IO.userError s!"audited module is absent from the imported environment: {value}")
  let rows := env.constants.fold
      (init := (Except.ok #[] : Except String (Array String))) fun result name info =>
    match result with
    | .error message => .error message
    | .ok rows =>
        let kind? :=
          match info with
          | .axiomInfo _ => some "axiom"
          | .opaqueInfo _ => some "opaque"
          | _ => none
        match kind? with
        | none => .ok rows
        | some kind =>
            match env.getModuleIdxFor? name with
            | none => .error s!"assumption has no source module attribution: {name}"
            | some index =>
                match env.header.moduleNames[index.toNat]? with
                | none => .error s!"assumption has an invalid source module index: {name}"
                | some sourceModule =>
                    if !auditedValues.contains sourceModule.toString then
                      .ok rows
                    else
                      .ok (rows.push s!"{kind}\t{sourceModule}\t{name}")
  let rows ←
    match rows with
    | .ok rows => pure rows
    | .error message => throw (IO.userError message)
  for row in rows.qsort (· < ·) do
    IO.println row
  pure 0
