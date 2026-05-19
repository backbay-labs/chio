# Wave 1A Figure Plan: Sensor-Grounded Admission

The paper currently carries zero figures across eighteen pages of dense prose. Three figures are proposed below. Each is grounded in load-bearing prose that already exists; none duplicates a passage that the prose already discharges in full. The first two are required; the third is optional and earns its place only if the §8 related-work survey is the load-bearing comparative artifact reviewers will lean on.

## Figure 1 (required): Sensor-state attestation field layout

### Title and label

Title: "Sensor-state attestation embedded in a signed receipt."
Label: `\label{fig:attestation-layout}`.

### Placement

§3 (`sections/03-substrate.tex`), immediately after the "Sensor-state attestation" paragraph (line 7) and before the "Clock state" paragraph. This is the first point in the paper where the reader is asked to hold an eleven-field provider record in working memory while also tracking the clock record and the joint-digest binding. The figure replaces the spatial-arrangement burden that the prose currently asks the reader to construct unaided.

### Skeleton

```
\begin{figure}[t]
\centering
\begin{tikzpicture}[
  every node/.style={font=\small},
  box/.style={draw, rounded corners=1pt, align=left, inner sep=4pt},
  hdr/.style={box, fill=black!4},
  att/.style={box, fill=black!8},
  rec/.style={box, font=\footnotesize\ttfamily}]
  \node[hdr, minimum width=8cm] (env) {DSSE envelope (Ed25519 over canonical-JSON)};
  \node[att, minimum width=8cm, below=2mm of env] (att) {
    \textbf{Sensor-state attestation}\\
    \texttt{providers}: list of provider records\\
    \texttt{clock}: \{capturedAt, source, synchronized, uncertaintyMs\}};
  \node[rec, below=2mm of att, minimum width=8cm] (rec) {%
    providerId | providerKind\\
    installed, active, healthy, degraded\\
    droppedEventCount, deadlineMissCount\\
    degradationReasons[]};
  \node[box, below=2mm of rec, minimum width=8cm] (body) {Receipt body};
  \draw[decorate,decoration={brace,amplitude=4pt,mirror}]
    (att.south west) -- (body.north west)
    node[midway, left=5pt, align=right]
    {covered by\\subject digest};
\end{tikzpicture}
\caption{The attestation is a first-class field of the receipt, not metadata: its canonical-JSON bytes are covered by the same subject digest as the body.}
\end{figure}
```

### Why it earns the page

The reader of §3 is told the attestation lists eleven fields per provider, carries a clock record, and is jointly signed with the body. Three flat lists of fields are hard to hold in prose; a single box diagram showing the receipt envelope, the attestation block (decomposed into the provider record and the clock record), and the joint-digest binding settles all three structural commitments in one glance. The caption hook is "this is what the verifier sees and decides on," which is exactly the framing §3 ends with.

## Figure 2 (required): Admission decision tree under the ladder-mode partition

### Title and label

Title: "Admission verdict as a function of the attestation's coverage of the constitution-required set."
Label: `\label{fig:ladder-decision}`.

### Placement

§4 (`sections/04-model.tex`), after the "Ladder structuring" paragraph and the destructive-floor projection (after line 62). The §4 model defines four admission outcomes and threads them through the parent paper's five-mode ladder; the reader carries Theorem 2 (partition-contingency biconditional) and Theorem 3 (destructive-admission projection) at this point. The figure makes the branch structure decidable on the attestation explicit and lets §5 (implementation) refer to it when it walks the four denial-code outcomes.

### Skeleton

```
\begin{figure}[t]
\centering
\begin{tikzpicture}[
  node distance=8mm,
  every node/.style={font=\small, align=center},
  decision/.style={diamond, draw, aspect=2, inner sep=1pt},
  verdict/.style={rectangle, draw, rounded corners=1pt, fill=black!5},
  arrow/.style={-latex}]
  \node[verdict] (start) {Receipt $\hat r = (r, A)$ arrives};
  \node[decision, below=of start] (parse) {Attestation parses?};
  \node[verdict, right=14mm of parse] (deny1) {Deny\\\texttt{attestation\_parse\_failed}};
  \node[decision, below=of parse] (cover) {$\mathsf{Req}_K \subseteq \mathsf{attestedHealthy}(A)$?};
  \node[decision, below right=8mm and 6mm of cover] (subset) {$\mathsf{attestedHealthy} \sqsubset \mathsf{Req}_K$?};
  \node[verdict, below=of cover] (rb) {Receipt-backed\\admission};
  \node[verdict, below=of subset] (pc) {Partition-contingency\\admission};
  \node[verdict, right=10mm of subset] (deny2) {Deny\\\texttt{required\_set\_uncovered}};
  \draw[arrow] (start) -- (parse);
  \draw[arrow] (parse) -- node[above]{no} (deny1);
  \draw[arrow] (parse) -- node[left]{yes} (cover);
  \draw[arrow] (cover) -- node[left]{yes} (rb);
  \draw[arrow] (cover) -- node[above right]{no} (subset);
  \draw[arrow] (subset) -- node[left]{yes} (pc);
  \draw[arrow] (subset) -- node[above]{no} (deny2);
\end{tikzpicture}
\caption{The attestation field is the decision input: covering the required set yields receipt-backed admission, a strict-sublist coverage yields partition-contingency, and the rest is denied under typed codes.}
\end{figure}
```

### Why it earns the page

The five-mode ladder is the central decision artifact the paper inherits from the parent and tightens in §4. Theorem 2 says partition-contingency is the strict-sublist case; the figure makes the strict-sublist branch a literal decision node and pins receipt-backed and denial outcomes at the two ends of the same tree. The reader can map any subsequent prose statement ("a quorum-required floor rejects partition-contingency outcomes," "destructive admission requires receipt-backed") onto a path through the figure. Observation and guarded modes sit below the destructive floor and are decided on the body alone (per §3); the figure annotates them as out-of-scope branches without cluttering the main path.

## Figure 3 (optional): TEE attestation family comparison table

### Title and label

Title: "TEE attestation wire formats: what they bind, and what they do not."
Label: `\label{tab:tee-comparison}`.

### Placement

§8 (`sections/08-related-work.tex`), inside the "TEE attestation and what its wire formats cannot express" paragraph. The current prose enumerates Intel TDX, AMD SEV-SNP, AWS Nitro, Apple PCC, and Arm CCA in running text and asserts that none expresses per-sensor drop or deadline-miss counts. The reader cannot easily verify that scope claim from running prose; a table makes the gap legible at a glance.

### Skeleton

```
\begin{table}[t]
\centering\footnotesize
\begin{tabular}{@{}lllll@{}}
\toprule
Family & Isolation primitive & Attestation root & Evidence format & Per-sensor counts \\
\midrule
Intel TDX        & VM-level TD           & Quote signing key & TDX Quote v4/v5  & no \\
AMD SEV-SNP      & Encrypted VM          & VCEK              & ATTESTATION\_REPORT & no \\
Arm CCA          & Realm world           & Realm Attestation Key & RATS EAT realm-token & no \\
Apple PCC        & Sealed compute node   & Node identity key & SealedHashLedger & no \\
AWS Nitro NSM    & Enclave (Firecracker) & NSM root          & COSE\_Sign1 PCR0--8 & no \\
TPM 2.0 (ref.)   & Platform              & EK / AK chain     & TPM\_QUOTE       & no \\
\addlinespace
This paper        & (composes above)     & (kernel key today)& Canonical-JSON   & yes \\
\bottomrule
\end{tabular}
\caption{Surveyed TEE wire formats bind launch and runtime measurement registers but do not express per-sensor drop counts, deadline misses, or the installed-versus-degraded distinction.}
\end{table}
```

### Why it earns the page

The §8 paragraph carries six primary citations and an explicit claim about what those formats cannot encode. The table converts that claim from a running prose assertion into a structural visual. The final row is the paper's positive claim against the same axes; reviewers who are TEE specialists can audit the comparison row by row rather than re-reading the paragraph. The risk is that the row "Per-sensor counts: no" reads like a polemical scorecard rather than a structural fact; the caption keeps it factual ("do not express") and the row labels keep it descriptive.

## Priority ranking

The two required figures are not interchangeable. The most load-bearing figure is Figure 2 (the admission decision tree). The paper's central claim is that the partition-contingency mode is decidable on the attestation field, and Theorems 1 through 4 together describe a structure that is easier to grasp as a tree than as four prose theorem statements. A reviewer who reads Figure 2's caption and traces one path through the diagram has the entire admission predicate in one glance.

Figure 1 (the attestation field layout) is the second priority. It is a reference figure rather than a load-bearing argument figure: it grounds §3 and §4 in a concrete data shape but does not, by itself, carry the paper's claim.

Figure 3 (the TEE comparison table) is the third priority. It is a survey artifact that strengthens §8 without being required for any other section to make sense. Drop it if the final page budget is tight; the §8 prose discharges the same claim, just less legibly.
