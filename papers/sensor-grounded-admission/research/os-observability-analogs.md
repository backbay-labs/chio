# OS observability literature analogs to `EndpointSensorState`

## Top finding

The single closest prior-art family the paper's §8 currently underweights is the **Linux audit subsystem plus its eBPF-replacement lineage**, not IMA. IMA (Sailer 2004) is correctly cited as the load-time / property-attestation anchor, but the structural pattern the paper actually rebuilds is what auditd and modern eBPF audit pipelines (`eAudit`, Tetragon, Falco) have been doing for fifteen years: counting dropped kernel events, exposing per-probe health, and surfacing "buffer overflowed under sustained load" as an observable scalar. The paper's `droppedEventCount` and `deadlineMissCount` fields are direct structural cousins of Falco's `n_drops_buffer`, `n_drops_pf`, and `n_drops_bug` counters and of auditd's `backlog_limit` overflow accounting. Critically, none of these systems signs the drop count and binds it to a downstream admission predicate, which is the paper's actual delta. The right §8 move is to cite them as the kernel-observability lineage the construction sits above, not as a missing competitor.

## eBPF observability

The eBPF subsystem exposes drop telemetry through several distinct channels that the paper's contribution map should engage. Falco's `scap.n_drops` family (verified against the project's troubleshooting docs and the modern-BPF release notes) decomposes kernel-side losses into buffer-pressure drops (`n_drops_buffer`), page-fault drops (`n_drops_pf`), and verifier-condition drops (`n_drops_bug`). These metrics are exported from the producer (kernel eBPF program) to userspace consumers, but are not signed; an attacker with userspace control over the Falco agent can rewrite the count before it is read.

Cilium Tetragon ships a parallel set of buffer-fullness and per-probe miss counters and adds a per-process attestation idea via the JSON event envelope. Neither Falco nor Tetragon exposes a canonical signed-attestation pattern for "this is the set of probes that were active when event X was emitted"; the kernel-to-userspace channel is unauthenticated and consumers must trust the agent.

The strongest academic anchor in this lineage is **Sekar et al., "eAudit: A Fast, Scalable and Deployable Audit Data Collection System," IEEE S&P 2024**. eAudit explicitly motivates itself by the fact that "existing popular tools like auditd and sysdig lose a majority of events under sustained workloads, and are vulnerable to log tampering" and is built on eBPF for high-throughput audit-data capture. The paper measures drop rates as a deployment property; it does not, however, attest them in the cryptographic sense. eAudit is the load-bearing eBPF-era observability cite the sensor-grounded paper should engage in §8.

A weaker but worth-mentioning thread: kernel commit 6.6 era work on the **BPF Token** mechanism for delegating verifier access into user namespaces, and ongoing eBPF-Foundation threat-model work on kernel-level signing of BPF programs, both move the ecosystem toward "the kernel attests which BPF programs are active." This is the public ground that comes closest to the paper's `EndpointSensorState` shape; it is engineering work in progress and lacks a single citable academic anchor, so a footnote naming the BPF Token docs is appropriate rather than a paragraph.

The structural delta over Falco / Tetragon / eAudit is clean: those systems produce drop counts as unauthenticated telemetry consumed for human-readable alerts; the paper's construction signs the drop count, binds it to the receipt's subject digest under DSSE, and feeds it into a constitution-controlled admission predicate that runs at the receipt boundary. The eBPF lineage is the substrate the new layer sits above.

## auditd

The Linux audit subsystem (Grubb, 2004 onward; included in kernel since 2.6) is the canonical prior art for "the OS counts what it dropped." The `backlog_limit` parameter caps the kernel-side queue of audit messages awaiting delivery to userspace `auditd`; when exceeded, the kernel's failure mode is configurable as silent / printk / panic (the `--failure` flag to `auditctl`). The system reports lost-event statistics through `auditctl -s`.

Crucially, auditd does **not** attest its own coverage in any cryptographic sense. There is no signed record of "audit rules X and Y were loaded; rule Z dropped events." The closest structural analog is the audit-rule-list snapshot returned by `auditctl -l`, which is local-only, unsigned, and trusts the running kernel. Red Hat's documentation on "audit backlog limit exceeded" troubleshooting (verified) describes the dropped-event accounting but treats it as a tuning problem, not a security property.

The structural delta over auditd is therefore precisely the paper's claim: lift the auditd drop-count surface into a signed attestation, bind it to the consumer-side decision boundary. This is the lineage move the paper should foreground.

## IMA / EVM

Sailer, Zhang, Jaeger, and van Doorn, "Design and Implementation of a TCG-based Integrity Measurement Architecture," **USENIX Security 2004** (verified) is the load-time-attestation paper, and the §8 cite is correct. The relevant subtlety the paper does not yet acknowledge: IMA itself has measurement-coverage gaps. The Gentoo IMA wiki and Bohling et al.'s "Subverting Linux' Integrity Measurement Architecture" (ARES 2020, verified) document that:

- The built-in `tcb` policy excludes files in tmpfs, a known coverage hole.
- IMA's runtime hooks (`ima_main.c` in mainline) cover binary load and file-open-by-root, but explicitly skip frequently-changing files (logs, databases), and the skip-list is configurable but not attested as part of the policy.
- A TOCTOU vulnerability identified in 2020 lets an attacker race the measurement against the execution.

IMA does not produce a "files I deliberately did not measure" attestation. Keylime's runtime IMA support (verified against project docs) treats the measurement list as canonical without a parallel coverage record. The "coverage of the measurement" is implicit in the IMA policy, which is itself loadable at runtime and is the responsibility of the local administrator.

The structural delta over IMA is the explicit coverage-attestation field. IMA says "here is what I measured." The paper's construction says "here is which sensors I tried to consult, here is which were healthy, here is which dropped events, signed." The two compose: an IMA-attesting kernel with a degraded behavioral-telemetry sensor is structurally degraded under the paper's predicate without weakening IMA's launch attestation.

EVM (Extended Verification Module) adds HMAC-signed extended attributes on the measurement-list entries and addresses tamper-resistance of the stored measurements. It does not address coverage gaps.

## Recommended §8 additions

The bibtex stubs the next FIX cycle can pick up:

```bibtex
@inproceedings{sekarEAudit2024,
  author = {Sekar, R. and Kimm, Hanke and Aich, Rohit},
  title = {{eAudit}: A Fast, Scalable and Deployable Audit Data Collection System},
  booktitle = {2024 IEEE Symposium on Security and Privacy (SP)},
  year = {2024},
  publisher = {IEEE},
  doi = {10.1109/SP54263.2024.00087}
}

@inproceedings{bohlingSubvertingIMA2020,
  author = {Bohling, Felix and M{\"u}ller, Tobias and Eckert, Michael and Lindemann, Jens},
  title = {Subverting Linux' Integrity Measurement Architecture},
  booktitle = {Proceedings of the 15th International Conference on Availability, Reliability and Security (ARES)},
  year = {2020},
  doi = {10.1145/3407023.3407058}
}

@misc{falcoDropTelemetry,
  author = {{The Falco Authors}},
  title = {Falco Is Dropping Syscalls Events (Troubleshooting Guide)},
  howpublished = {\url{https://falco.org/docs/troubleshooting/dropping/}},
  year = {2024}
}

@misc{cilliumTetragon,
  author = {{Isovalent}},
  title = {Cilium {Tetragon}: eBPF-based Security Observability and Runtime Enforcement},
  howpublished = {Project documentation, \url{https://tetragon.io}},
  year = {2024}
}

@inproceedings{sadeghiPBA2004,
  author = {Sadeghi, Ahmad-Reza and St{\"u}ble, Christian},
  title = {Property-Based Attestation for Computing Platforms: Caring About Properties, Not Mechanisms},
  booktitle = {New Security Paradigms Workshop (NSPW)},
  year = {2004},
  pages = {67--77},
  doi = {10.1145/1065907.1066038}
}
```

The Sadeghi-Stüble PBA cite is added here because the proposals/03 set surfaces Haldar 2004 as the property-attestation anchor but the NSPW 2004 paper is the version reviewers in trusted-computing circles actually reach for; both should appear together.

## Structural delta argument

None of the cited prior art binds the kernel-coverage attestation to a downstream admission predicate evaluated at the receipt boundary of a polity constitution. IMA attests boot-time and access-time measurement events to a TPM and exposes them to a remote challenger; auditd records dropped events for forensic review; Falco / Tetragon / eAudit ship the same signal through eBPF for higher fidelity. The Sailer / Haldar / Coker / Sadeghi property-attestation lineage formalizes "the verifier accepts iff the attested system has the property the verifier requires," and the sensor-grounded paper is, on its face, a member of that lineage. The irreducible novelty is the placement: a per-receipt rolling state that lives inside a bilateral-treaty admission predicate and discharges a re-attestation obligation under constitutional amendment. The kernel-observability layer is canon; the constitutional layer above it is not. The honest §8 framing names IMA / auditd / eAudit as the OS-side substrate the construction sits above and Sadeghi-Stüble / Coker as the formal-attestation lineage it inherits from, then names the constitution-as-admission-predicate as the delta.
