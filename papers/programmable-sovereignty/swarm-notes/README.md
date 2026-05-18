# Swarm review notes

A recurring review swarm runs every 10 minutes for 8 iterations total. Each iteration spawns 3-4 review agents that read prior iteration notes and add new observations to a single iteration file. Agents do NOT modify the paper or any other artifact -- they observe and write notes only.

## Structure

- `iteration-counter.txt` -- current iteration number (0 to 8); the orchestrator increments this each fire.
- `iteration-01.md` through `iteration-08.md` -- one file per iteration; each iteration's agents append their sections.
- `synthesis.md` -- created after iteration 8 with rolled-up findings (manually triggered or by a final synthesis agent).

## Diversity strategy

Each iteration rotates agent personas so the swarm covers different attack surfaces over time without re-treading. Suggested rotation (iteration N out of 8):

1. Hostile NDSS reviewer (fresh hostile read with the polish-diff context)
2. PL / formal-methods skeptic (Lean source + theorem inventory)
3. Industry deployment practitioner (operational gaps, scale story)
4. Adversarial threat-model brainstormer (attacks not yet enumerated)
5. Cross-paper positioning (recent papers the bibliography should engage)
6. Naive smart reader (cold-read elevator pitch test)
7. Foundational-theory connection seeker (political theory / type theory / mechanism design)
8. Strategic / tactical (cosigner sequence, killer-app pick, what to NOT do)

Each iteration is free to draw from this list or invent its own personas. The constraint is: read prior iteration notes first, do not duplicate prior findings, focus on what hasn't been said.

## Reading order for agents

Every agent should read, in this order:
1. `papers/programmable-sovereignty/paper.tex`
2. Relevant section sources under `papers/programmable-sovereignty/sections/`
3. `papers/programmable-sovereignty/polish-diff.md` (cumulative history of all prior passes)
4. `papers/programmable-sovereignty/swarm-notes/iteration-*.md` for all prior iterations
5. Their own assigned focus area

## Output discipline

- One section per agent in the current iteration file, headed by the agent's persona name.
- Under 500 words per agent.
- Cite section + line where possible.
- Open with one sentence stating the most important new observation.
- Each agent ends with a single "highest-priority follow-up" recommendation.

## Stop condition

The orchestrator halts after iteration 8 is written. No further wake-ups are scheduled.
