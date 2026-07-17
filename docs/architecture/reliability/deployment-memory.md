# Memory deployment guidance

The goal, following the Ubicloud PostgreSQL/OOM-killer lesson, is that
allocations fail early and locally (returning to the `try_reserve` and shed
paths) rather than the OOM killer picking a victim later. The mediator has
two in-process backstops: bounded collections (every long-lived
serving collection has a capacity policy and a live `SizeGauge`, enumerated by
`ChioKernel::bounded_structure_gauges`) and an RSS soft ceiling
(`MemoryBudgetConfig::rss_soft_limit_bytes`) that sheds new admissions with
`KernelError::Overloaded { resource: Allocation }` before the process is killed.
This appendix covers the OS-level configuration that makes those backstops
effective. Restart-policy and process-supervision configuration is out of scope
here.

## cgroup v2 memory limits

Run the mediator under a cgroup v2 slice with both a soft and a hard limit:

- `memory.high` -- the throttle/reclaim threshold. Set the process
  `rss_soft_limit_bytes` to roughly this value (about 85-90% of `memory.max`)
  so the in-process shed fires at or just before the kernel starts aggressive
  reclaim.
- `memory.max` -- the hard limit. Crossing it triggers cgroup OOM. The soft
  ceiling and the bounded collections are sized so the process sheds and stays
  flat well under this line.

Example (systemd slice or `cgroupfs`):

```
memory.high = 3.5G
memory.max  = 4G
```

with `MemoryBudgetConfig::rss_soft_limit_bytes = Some(3_600_000_000)`.

## Strict overcommit

Set the kernel to strict overcommit accounting so a large allocation fails at
`malloc`/`mmap` time (surfacing as a Rust allocation error the `try_reserve`
paths convert to `Overloaded { Allocation }`) rather than succeeding and being
reaped later:

```
vm.overcommit_memory = 2
vm.overcommit_ratio  = 80   # tune per host RAM + swap
```

Under strict overcommit the `push_chunk_bounded` `try_reserve` path and other
fallible reservations turn an out-of-memory condition into a typed deny instead
of an abort.

## OOM score ordering

If the OOM killer does run, it must pick the untrusted sidecar first and the
kernel TCB last. Order `oom_score_adj` so the least-trusted, most-replaceable
process is the preferred victim:

- untrusted tool sidecar / connector: `oom_score_adj = +500` (killed first)
- agent-facing edge process: `oom_score_adj = 0`
- kernel mediator (TCB): `oom_score_adj = -500` (killed last)

## Per-process address-space cap

Cap the mediator's virtual address space with `RLIMIT_AS` as a final backstop so
a runaway allocation fails locally:

```
setrlimit(RLIMIT_AS, soft = hard = memory.max)
```

## systemd equivalents

When the mediator runs as a systemd unit, the above map to unit directives:

```ini
[Service]
MemoryHigh=3.5G
MemoryMax=4G
OOMScoreAdjust=-500
LimitAS=4G
```

Set the untrusted sidecar unit's `OOMScoreAdjust=500` so it is the preferred
victim, and leave the mediator's `rss_soft_limit_bytes` at roughly `MemoryHigh`.

## Non-Linux hosts

The `/proc/self/statm` sampler is Linux-only; on other hosts it is a no-op and
the RSS soft ceiling is inert. The cgroup/overcommit backstops are also
Linux-specific, but the bounded collections and the `try_reserve` shed paths
still apply on every platform, so memory stays bounded regardless.
