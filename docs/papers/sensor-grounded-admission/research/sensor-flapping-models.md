# Sensor-flapping and intermittent-failure models in prior art

## Top finding

The paper does not need to weaken its headline claim, but it does need to **strengthen the model definition and cite three specific bodies of work**. The structural-distinguishability theorem holds under any sensor-state model that records a categorical health field per provider; what fails to match production reality is the implicit assumption that the field reflects a stable two-state condition over the decision window. The fix is one of the following, in increasing order of intrusiveness: (a) restate the claim explicitly as "structurally distinguishable under stable sensor state, with within-window flapping deferred to future work" and cite Cardenas-Amin-Sastry plus phi-accrual; (b) add a flapping-tolerance threshold field (`flap_rate_hz` or `transition_count`) to the schema and rerun the proof; (c) replace the binary state with a Beta-distributed trust posterior in the Saroiu-Wolman / MATE Multi-Agent Trust Estimator lineage. Option (a) is the cheapest and is the recommended verdict; the contribution survives. Option (c) is interesting future work that becomes a separate paper.

The single most load-bearing observation: the prior art does not have a *cryptographic-attestation* analog of triple-modular-redundancy voting. Aerospace solved sensor flapping with hardware redundancy plus mid-value-select voting (Yeh 1996 on the Boeing 777 PFC); ICS solved it with state-aware invariants over the physical-process model (SAIN, USENIX Security 2024); distributed systems solved it with continuous-suspicion failure detectors (phi-accrual, Hayashibara et al., SRDS 2004). None of these is a signed attestation that flapping occurred. The paper's construction therefore inherits an honest model gap rather than a fatal one, and naming the gap is sufficient.

## ICS / SCADA

The OT-security community has the most mature model. The canonical citations are:

- **Cardenas, Amin, Sastry, "Research Challenges for the Security of Control Systems," HotSec 2008** (verified at the USENIX legacy site). Defines the problem of *deception attacks* in which an adversary sends false sensor readings to a controller, and *DoS attacks* in which an adversary suppresses sensor readings. Sensor-flapping is structurally the boundary between the two: a sensor that intermittently delivers correct readings and intermittently delivers nothing or noise.

- **Cardenas, Amin, Sastry, "Secure Control: Towards Survivable Cyber-Physical Systems," ICDCS Workshops 2008** (verified). The longer companion. Argues that classical anomaly detectors confuse "sensor lying" with "sensor failing" and that the cyber-physical-systems threat model needs to handle both.

- **Mitchell and Chen, "A Survey of Intrusion Detection Techniques for Cyber-Physical Systems," ACM Computing Surveys 2014** (verified, volume 46 article 55). Surveys 28 CPS IDS systems and classifies them by detection technique and audit material. Treats sensor state as inferred from observed behavior, not as witnessed; this is the dominant pattern in the field.

- **Pasqualetti, Dörfler, Bullo, "Attack Detection and Identification in Cyber-Physical Systems," IEEE Transactions on Automatic Control 2013** (verified, vol 58 case 11). Formal framework where attacks are exogenous unknown inputs to a linear descriptor system. Sensor flapping appears as a particular structure on the unknown-input signal.

- **Krotofil, Larsen, Gollmann, "The Process Matters: Ensuring Data Veracity in Cyber-Physical Systems," AsiaCCS 2015** (verified; Krotofil's process-aware detection work). Detects sensor signals being maliciously manipulated by reasoning about plant-process dynamics. Krotofil's earlier 2014 work on stale-data vulnerabilities and the optimal time to launch attacks is the source for the paper's "stale attestation" concern.

- **Abbas et al., "SAIN: Improving ICS Attack Detection Sensitivity via State-Aware Invariants," USENIX Security 2024** (verified). The current state of the art. Partitions PLC traces into state-specific sub-traces with tight invariant bounds per state and detects attacks that would fit inside loose state-agnostic bounds. Achieves 2% FPR / 3% overhead on 17 attacks against a manufacturing plant and chemical-plant simulator. This is the most relevant *recent* citation; the sensor-grounded paper's defenders should engage it.

The formal model across this lineage is consistent: a sensor produces a continuous signal $y(t) = h(x(t)) + v(t) + a(t)$ where $v$ is measurement noise and $a$ is an adversary-controlled additive term that captures lying, flapping, or suppression. None of this work treats sensor state as a *cryptographically attested* category. The categorical-attestation move is novel relative to ICS/SCADA detection literature.

## Distributed-systems failure detectors

The closest prior art is the phi-accrual lineage:

- **Chandra and Toueg, "Unreliable Failure Detectors for Reliable Distributed Systems," Journal of the ACM 1996** (verified, vol 43 case 2). Establishes that failure detectors are characterized by completeness and accuracy. Eventually-strong $\diamondsuit S$ is sufficient for consensus when a majority is correct. The two-state healthy/degraded model the paper uses is structurally the binary-output failure detector this work generalized.

- **Hayashibara, Défago, Yared, Katayama, "The Phi Accrual Failure Detector," SRDS 2004** (verified). Replaces the binary up/down output with a continuous suspicion value $\phi$ derived from the inter-arrival history of heartbeats. Used in Cassandra and Akka. The motivation is *exactly* the paper's adversarial-review concern: short timeouts produce false positives, long timeouts produce false negatives, and the binary model loses the tradeoff information.

- **Chen, Toueg, Aguilera, "On the Quality of Service of Failure Detectors," IEEE Transactions on Computers 2002.** Defines QoS metrics for failure detectors (mistake recurrence time, mistake duration, detection time). Provides the formal vocabulary for "this detector flaps."

None of this lineage treats sensor state as a *witnessed-attestation* rather than an inferred probability. The phi-accrual community continuously infers a suspicion value from observed heartbeat timing; the sensor-grounded paper signs a discrete categorical claim about state at a single moment. These two approaches are complementary, and a stronger version of the paper could replace the binary `healthy: bool` field with a continuous `suspicionLevel: f64` field analogous to phi, but the structural-distinguishability theorem still holds. **The honest move is to cite Hayashibara et al. and acknowledge that the categorical state is a discretization of a continuous suspicion signal, and that the discretization threshold is a constitutional parameter.**

Bayesian sensor-fusion / Dempster-Shafer evidence theory (Wikipedia + 2021-2023 multi-sensor-fusion literature, verified) treats sensor reliability as belief masses combined via Dempster's rule. Recent work on "Trust-Based Assured Sensor Fusion in Distributed Aerial Autonomy" (arXiv 2025) and the MATE (Multi-Agent Trust Estimator, arXiv 2503.04954) papers cast trust estimation as a hidden Markov model with Beta-distributed posteriors. These are all *inference* frameworks; none signs the resulting trust value into an attestation. The sensor-grounded paper sits orthogonally.

## Aerospace / safety-critical

Aerospace handled sensor flapping with redundancy + voting, not attestation:

- **Yeh, "Triple-Triple Redundant 777 Primary Flight Computer," IEEE Aerospace Applications Conference 1996** (verified). The Boeing 777 PFC uses three channels, each with three dissimilar computation lanes. All three inputs are compared and a *mid-value select* is computed on the three LRRA (Low-Range Radio Altimeter) inputs, so a single sensor failure that produces an erroneous value is discarded by the median. This is the canonical safety-critical answer to sensor flapping.

- **Yeh, "Design Considerations in Boeing 777 Fly-By-Wire Computers," DSN 1998** (verified). Long-form follow-up. Covers N-version dissimilarity, fault containment regions, deferred-maintenance design.

- **ARINC 653** (verified against the standard's secondary sources). The avionics RTOS partitioning standard. Includes a *health monitor* function responsible for identifying, responding to, and reporting hardware and partition faults. The health monitor's records are *not* cryptographically signed for downstream consumption; ARINC 653 is concerned with reaction policy, not external attestation.

The structural answer in aerospace is: trust the hardware redundancy, vote, fail safe, never let a single sensor's flapping reach the controller. There is no published *cryptographic* attestation analog. The sensor-grounded paper's move (sign the flapping as a first-class field) is therefore novel relative to aerospace literature, though the obvious next paper would compose the two: a TMR-voted sensor produces a single signed reading whose voting record is part of the attestation.

## The "structural distinguishability under measurement noise" question - verdict

The paper claims `admission_under_degraded_state_distinguishable_from_healthy`: there exists a body and two attestations producing opposite admission verdicts. The concern is that the categorical healthy / degraded state collapses real-world flapping into a single bit and the attestation thus carries less information than the threat model assumes.

The verdict: **the theorem survives, the model description does not.** The theorem is a Σ-type existence claim and is trivially true for any provider taxonomy that contains at least one provider with at least two distinguishable states. What does *not* survive without patching is the implicit prose claim that the categorical state faithfully represents the kernel's posture over the decision window.

Recommended language: the paper should add a paragraph in §3 (the model section) that explicitly states the discretization choice, cites Hayashibara phi-accrual as the continuous-state alternative, cites Cardenas-Amin-Sastry plus Mitchell-Chen as the CPS lineage that addresses within-window oscillation under measurement noise, and defers the within-window-flapping-tolerance threshold to future work. §9 (limitations) should name the within-window flapping concern explicitly. With those two paragraphs added, the contribution is correctly scoped and survives the new prior art.

The strongest possible attack on the paper from this angle (a SAIN-style reviewer arguing that state-aware invariants subsume the categorical attestation) is answered by the placement argument: SAIN runs invariant checks at a PLC monitor; the paper's construction runs predicates at a constitutional admission boundary. The two are at different layers and compose. The reviewer pushback to *anticipate* is "your healthy / degraded discretization is throwing away information that phi-accrual would retain"; the response is that the discretization threshold is a constitutional parameter, that the schema is extensible to continuous suspicion, and that the v1 schema deliberately starts categorical to keep the admission predicate decidable. That answer requires the §3 paragraph and the §9 limitation; without them, the reviewer wins.
