# chio-workflow

`chio-workflow` is the skill and workflow authority for Chio. It extends the
capability model with multi-step skill composition, where a skill is an ordered
sequence of tool invocations with declared I/O contracts, dependency
relationships, and budget envelopes. It defines `SkillGrant` (the
capability-model extension for ordered tool sequences), `SkillManifest`
(tool dependencies, I/O contracts, budget), and workflow receipts.

Use this crate to compose and govern multi-step skills on top of single-tool
Chio capabilities.
