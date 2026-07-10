import type {
  ProofRoomBundleManifest,
  ProofRoomCommerceEvidence,
  ProofRoomCryptoContextEvidence,
  ProofRoomDisclosureEvidence,
  ProofRoomEnterpriseEvidence,
  ProofRoomRuntimeEvidence,
  ProofRoomSwarmEvidence,
  ProofRoomTrustMarketEvidence,
} from './types'

export interface ProofRoomArtifactSourceRef {
  path: string
  sha256: string
  schema: string
  renderer_hint?: string
}

export interface ProofRoomArtifactEvidenceSpec<TEvidence> {
  key: keyof TEvidence
  schema: string
  rendererHint: string
  label: string
  multiple?: boolean
}

export type ProofRoomArtifactReader = <T extends { schema: string }>(
  artifact: ProofRoomArtifactSourceRef,
  label: string,
) => Promise<T>

export interface ProofRoomArtifactText {
  contents: string
  digestable?: boolean
}

export interface ProofRoomDsseSignature {
  payloadType?: string
  payloadRef?: ProofRoomArtifactSourceRef
  signatures?: Array<{ keyid?: string; sig?: string }>
}

export type ProofRoomArtifactTextReader = (
  artifact: ProofRoomArtifactSourceRef,
  label: string,
) => Promise<string | ProofRoomArtifactText>

const proofRoomBundlePayloadType = 'application/vnd.chio.proof-room.bundle.v1+json'
const proofRoomTrustedBundleSignersPath = '/proof-room-trusted-bundle-signers.json'
const proofRoomTrustedBundleSignersSchema = 'chio.proof-room.trusted-bundle-signers.v1'

export async function sha256Hex(contents: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(contents))
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

export async function assertProofRoomArtifactDigest(
  contents: string,
  expectedSha256: string,
  label: string,
): Promise<void> {
  const actualSha256 = await sha256Hex(contents)
  if (actualSha256 !== expectedSha256) {
    throw new Error(`${label} digest does not match the manifest`)
  }
}

export function assertProofRoomBundleRelativePath(path: string): void {
  if (
    !path
    || path.startsWith('/')
    || path.includes('\\')
    || path.includes(':')
    || path.includes('//')
    || hasWhitespaceOrControl(path)
    || /^[A-Za-z]:/.test(path)
  ) {
    throw new Error(`unsafe Proof Room asset path: ${path}`)
  }
  let sawComponent = false
  for (const segment of path.split('/')) {
    if (isUnsafeProofRoomPathSegment(segment)) {
      throw new Error(`unsafe Proof Room asset path: ${path}`)
    }
    sawComponent = true
  }
  if (!sawComponent) {
    throw new Error(`unsafe Proof Room asset path: ${path}`)
  }
}

export function isUnsafeProofRoomPathSegment(segment: string): boolean {
  if (segment === '' || segment === '.' || segment === '..') {
    return true
  }
  let decodedSegment: string
  try {
    decodedSegment = decodeURIComponent(segment)
  } catch {
    return true
  }
  return decodedSegment === ''
    || decodedSegment === '.'
    || decodedSegment === '..'
    || decodedSegment.includes('/')
    || decodedSegment.includes('\\')
    || hasWhitespaceOrControl(decodedSegment)
}

function hasWhitespaceOrControl(value: string): boolean {
  for (const character of value) {
    if (/\s/u.test(character) || character.codePointAt(0)! < 0x20 || character.codePointAt(0)! === 0x7f) {
      return true
    }
  }
  return false
}

function hexToBytes(value: string, label: string): Uint8Array {
  if (!/^[0-9a-f]+$/iu.test(value) || value.length % 2 !== 0) {
    throw new Error(`${label} is not valid hex`)
  }
  const bytes = new Uint8Array(value.length / 2)
  for (let index = 0; index < value.length; index += 2) {
    bytes[index / 2] = Number.parseInt(value.slice(index, index + 2), 16)
  }
  return bytes
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((total, chunk) => total + chunk.byteLength, 0)
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return bytes
}

function dssePreAuthEncoding(payloadType: string, payload: string): Uint8Array {
  const encoder = new TextEncoder()
  const payloadTypeBytes = encoder.encode(payloadType)
  const payloadBytes = encoder.encode(payload)
  return concatBytes([
    encoder.encode(`DSSEv1 ${payloadTypeBytes.byteLength} `),
    payloadTypeBytes,
    encoder.encode(` ${payloadBytes.byteLength} `),
    payloadBytes,
  ])
}

export async function fetchProofRoomTrustedBundleSignerKeys(label: string): Promise<Set<string>> {
  let response: Response
  try {
    response = await fetch(proofRoomTrustedBundleSignersPath)
  } catch {
    throw new Error(`${label} trusted signer config missing`)
  }
  if (!response.ok) {
    throw new Error(`${label} trusted signer config missing`)
  }
  const config = await response.json() as { schema?: string; keys?: unknown[] }
  if (config.schema !== proofRoomTrustedBundleSignersSchema) {
    throw new Error(`${label} trusted signer config schema is unsupported`)
  }
  if (!Array.isArray(config.keys) || config.keys.length === 0) {
    throw new Error(`${label} trusted signer config missing`)
  }
  const keys = new Set<string>()
  for (const key of config.keys) {
    if (typeof key !== 'string' || key.length === 0) {
      throw new Error(`${label} trusted signer config key is invalid`)
    }
    const normalizedKey = key.toLowerCase()
    hexToBytes(normalizedKey, `${label} trusted signer key`)
    keys.add(normalizedKey)
  }
  if (keys.size === 0) {
    throw new Error(`${label} trusted signer config missing`)
  }
  return keys
}

export async function assertProofRoomBundleDsseSignature(
  signature: ProofRoomDsseSignature,
  manifestText: string,
  label: string,
  trustedSignerKeys?: Set<string>,
): Promise<void> {
  if (signature.payloadType !== proofRoomBundlePayloadType) {
    throw new Error(`${label} payload type does not match Proof Room manifests`)
  }
  if (signature.payloadRef?.path !== 'manifest.json') {
    throw new Error(`${label} payload path does not match manifest.json`)
  }
  if (signature.payloadRef?.schema !== 'chio.proof-room.bundle.v1') {
    throw new Error(`${label} payload schema does not match Proof Room manifests`)
  }
  if (!signature.payloadRef) {
    throw new Error(`${label} payload path does not match manifest.json`)
  }
  const manifestDigest = await sha256Hex(manifestText)
  if (signature.payloadRef.sha256 !== manifestDigest) {
    throw new Error(`${label} payload digest does not match the manifest`)
  }
  if (!signature.signatures || signature.signatures.length === 0) {
    throw new Error(`${label} has no signatures`)
  }
  if (signature.signatures.some((entry) => !entry.keyid || !entry.sig)) {
    throw new Error(`${label} entry is incomplete`)
  }
  if (!trustedSignerKeys || trustedSignerKeys.size === 0) {
    throw new Error(`${label} trusted signer config missing`)
  }
  const signedPayload = dssePreAuthEncoding(signature.payloadType, manifestText)
  for (const entry of signature.signatures) {
    const keyId = (entry.keyid ?? '').toLowerCase()
    if (!trustedSignerKeys.has(keyId)) {
      throw new Error(`${label} signer is not trusted`)
    }
    const keyBytes = hexToBytes(keyId, `${label} key`)
    const signatureBytes = hexToBytes(entry.sig ?? '', label)
    let publicKey: CryptoKey
    try {
      publicKey = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'Ed25519' },
        false,
        ['verify'],
      )
    } catch {
      throw new Error(`${label} key is invalid`)
    }
    const verified = await crypto.subtle.verify(
      { name: 'Ed25519' },
      publicKey,
      signatureBytes,
      signedPayload,
    )
    if (!verified) {
      throw new Error(`${label} verification failed`)
    }
  }
}

export async function readProofRoomArtifactSourceText(
  artifact: ProofRoomArtifactSourceRef,
  label: string,
  readArtifactText: ProofRoomArtifactTextReader,
): Promise<string> {
  const sourceText = await readArtifactText(artifact, label)
  if (typeof sourceText === 'string') {
    return sourceText
  }
  if (sourceText.digestable !== false) {
    await assertProofRoomArtifactDigest(sourceText.contents, artifact.sha256, label)
  }
  return sourceText.contents
}

export function proofRoomArtifactReader(
  readArtifactText: ProofRoomArtifactTextReader,
): ProofRoomArtifactReader {
  return async <T extends { schema: string }>(
    artifact: ProofRoomArtifactSourceRef,
    label: string,
  ) => JSON.parse(await readProofRoomArtifactSourceText(artifact, label, readArtifactText)) as T
}

export function manifestArtifactBySchemaOrHint(
  manifest: ProofRoomBundleManifest,
  schema: string,
  rendererHint: string,
): ProofRoomArtifactSourceRef | undefined {
  return manifest.artifacts?.find(
    (artifact) => artifact.schema === schema || artifact.renderer_hint === rendererHint,
  )
}

export function manifestArtifactsBySchemaOrHint(
  manifest: ProofRoomBundleManifest,
  schema: string,
  rendererHint: string,
): ProofRoomArtifactSourceRef[] {
  return (manifest.artifacts ?? []).filter(
    (artifact) => artifact.schema === schema || artifact.renderer_hint === rendererHint,
  )
}

export async function readProofRoomArtifacts<T extends { schema: string }>(
  manifest: ProofRoomBundleManifest,
  schema: string,
  rendererHint: string,
  label: string,
  sourceLabel: 'selected' | 'served',
  readArtifact: ProofRoomArtifactReader,
): Promise<T[]> {
  return Promise.all(
    manifestArtifactsBySchemaOrHint(manifest, schema, rendererHint).map(async (artifact) => {
      const report = await readArtifact<T>(artifact, `${sourceLabel} ${label}`)
      if (report.schema !== schema) {
        throw new Error(`${sourceLabel} ${label} has unsupported schema`)
      }
      return report
    }),
  )
}

export async function readProofRoomArtifact<T extends { schema: string }>(
  manifest: ProofRoomBundleManifest,
  schema: string,
  rendererHint: string,
  label: string,
  sourceLabel: 'selected' | 'served',
  readArtifact: ProofRoomArtifactReader,
): Promise<T | undefined> {
  const artifact = manifestArtifactBySchemaOrHint(manifest, schema, rendererHint)
  if (!artifact) {
    return undefined
  }

  const report = await readArtifact<T>(artifact, `${sourceLabel} ${label}`)
  if (report.schema !== schema) {
    throw new Error(`${sourceLabel} ${label} has unsupported schema`)
  }
  return report
}

export async function readProofRoomArtifactEvidence<TEvidence extends object>(
  manifest: ProofRoomBundleManifest,
  specs: readonly ProofRoomArtifactEvidenceSpec<TEvidence>[],
  sourceLabel: 'selected' | 'served',
  readArtifact: ProofRoomArtifactReader,
): Promise<TEvidence | undefined> {
  return collectProofRoomArtifactEvidence(specs, (spec) =>
    readProofRoomArtifacts<{ schema: string }>(
      manifest,
      spec.schema,
      spec.rendererHint,
      spec.label,
      sourceLabel,
      readArtifact,
    ),
  )
}

export async function collectProofRoomArtifactEvidence<TEvidence extends object>(
  specs: readonly ProofRoomArtifactEvidenceSpec<TEvidence>[],
  loadArtifacts: (spec: ProofRoomArtifactEvidenceSpec<TEvidence>) => Promise<unknown[]>,
): Promise<TEvidence | undefined> {
  const artifactLists = await Promise.all(specs.map((spec) => loadArtifacts(spec)))

  if (artifactLists.every((artifacts) => artifacts.length === 0)) {
    return undefined
  }

  const evidence: Record<string, unknown> = {}
  specs.forEach((spec, index) => {
    evidence[String(spec.key)] = spec.multiple ? artifactLists[index] : artifactLists[index][0]
  })
  return evidence as TEvidence
}

export const COMMERCE_EVIDENCE_SPECS: readonly ProofRoomArtifactEvidenceSpec<ProofRoomCommerceEvidence>[] = [
  {
    key: 'orderContext',
    schema: 'chio.commerce.order-context.v1',
    rendererHint: 'commerce-order-context',
    label: 'commerce order context',
  },
  {
    key: 'paymentLifecycle',
    schema: 'chio.commerce.payment-lifecycle.v1',
    rendererHint: 'commerce-payment-lifecycle',
    label: 'commerce payment lifecycle',
  },
  {
    key: 'eventLog',
    schema: 'chio.commerce.event-log.v1',
    rendererHint: 'commerce-event-log',
    label: 'commerce event log',
  },
]

export const DISCLOSURE_EVIDENCE_SPECS: readonly ProofRoomArtifactEvidenceSpec<ProofRoomDisclosureEvidence>[] = [
  {
    key: 'capsule',
    schema: 'chio.disclosure.capsule.v1',
    rendererHint: 'disclosure-capsule',
    label: 'disclosure capsule',
  },
  {
    key: 'signedLineageSubgraph',
    schema: 'chio.lineage.signed-subgraph.v1',
    rendererHint: 'signed-lineage-subgraph',
    label: 'signed lineage subgraph',
  },
  {
    key: 'leakageLedger',
    schema: 'chio.disclosure.leakage-ledger.v1',
    rendererHint: 'disclosure-leakage-ledger',
    label: 'disclosure leakage ledger',
  },
]

export const RUNTIME_EVIDENCE_SPECS: readonly ProofRoomArtifactEvidenceSpec<ProofRoomRuntimeEvidence>[] = [
  {
    key: 'executionLease',
    schema: 'chio.runtime.execution-lease.v1',
    rendererHint: 'execution-lease',
    label: 'runtime execution lease',
  },
  {
    key: 'revocationFreshnessProof',
    schema: 'chio.runtime.revocation-freshness-proof.v1',
    rendererHint: 'revocation-freshness-proof',
    label: 'runtime revocation freshness proof',
  },
  {
    key: 'sandboxAttestation',
    schema: 'chio.runtime.sandbox-attestation.v1',
    rendererHint: 'sandbox-attestation',
    label: 'runtime sandbox attestation',
  },
  {
    key: 'toolServerAck',
    schema: 'chio.runtime.tool-server-ack.v1',
    rendererHint: 'tool-server-ack',
    label: 'runtime tool-server acknowledgement',
  },
]

export const CRYPTO_CONTEXT_EVIDENCE_SPECS: readonly ProofRoomArtifactEvidenceSpec<ProofRoomCryptoContextEvidence>[] = [
  {
    key: 'verificationContext',
    schema: 'chio.crypto.verification-context.v1',
    rendererHint: 'crypto-verification-context',
    label: 'crypto verification context',
  },
  {
    key: 'keyState',
    schema: 'chio.trust.key-state.v1',
    rendererHint: 'trust-key-state',
    label: 'trust key state',
  },
  {
    key: 'revocationSnapshot',
    schema: 'chio.trust.revocation-snapshot.v1',
    rendererHint: 'trust-revocation-snapshot',
    label: 'trust revocation snapshot',
  },
  {
    key: 'privacyProfile',
    schema: 'chio.disclosure.verifier-privacy-profile.v1',
    rendererHint: 'disclosure-verifier-privacy-profile',
    label: 'disclosure verifier privacy profile',
  },
  {
    key: 'transparencyProof',
    schema: 'chio.transparency.inclusion-proof.v1',
    rendererHint: 'transparency-inclusion-proof',
    label: 'transparency inclusion proof',
  },
  {
    key: 'cryptoContextReport',
    schema: 'chio.disclosure.crypto-context-report.v1',
    rendererHint: 'disclosure-crypto-context-report',
    label: 'disclosure crypto context report',
  },
]

export const SWARM_EVIDENCE_SPECS: readonly ProofRoomArtifactEvidenceSpec<ProofRoomSwarmEvidence>[] = [
  {
    key: 'taskGraph',
    schema: 'chio.swarm.task-graph.v1',
    rendererHint: 'swarm-task-graph',
    label: 'swarm task graph',
  },
  {
    key: 'continuations',
    schema: 'chio.swarm.continuation-token.v1',
    rendererHint: 'swarm-continuation-token',
    label: 'swarm continuation token',
    multiple: true,
  },
  {
    key: 'witnessChains',
    schema: 'chio.swarm.delegation-witness-chain.v1',
    rendererHint: 'swarm-delegation-witness-chain',
    label: 'swarm delegation witness chain',
    multiple: true,
  },
  {
    key: 'routePlans',
    schema: 'chio.swarm.route-plan-receipt.v1',
    rendererHint: 'swarm-route-plan-receipt',
    label: 'swarm route plan receipt',
    multiple: true,
  },
  {
    key: 'joinReceipt',
    schema: 'chio.swarm.join-receipt.v1',
    rendererHint: 'swarm-join-receipt',
    label: 'swarm join receipt',
  },
  {
    key: 'budgetPool',
    schema: 'chio.swarm.budget-pool.v1',
    rendererHint: 'swarm-budget-pool',
    label: 'swarm budget pool',
  },
  {
    key: 'revocationEpoch',
    schema: 'chio.swarm.revocation-epoch.v1',
    rendererHint: 'swarm-revocation-epoch',
    label: 'swarm revocation epoch',
  },
]

export const ENTERPRISE_EVIDENCE_SPECS: readonly ProofRoomArtifactEvidenceSpec<ProofRoomEnterpriseEvidence>[] = [
  {
    key: 'exportBundle',
    schema: 'chio.enterprise.evidence-export-bundle.v1',
    rendererHint: 'enterprise-evidence-export-bundle',
    label: 'enterprise evidence export bundle',
  },
  {
    key: 'dataGovernanceReport',
    schema: 'chio.enterprise.data-governance-report.v1',
    rendererHint: 'enterprise-data-governance-report',
    label: 'enterprise data governance report',
  },
  {
    key: 'telemetryProjection',
    schema: 'chio.enterprise.telemetry-projection.v1',
    rendererHint: 'enterprise-telemetry-projection',
    label: 'enterprise telemetry projection',
  },
  {
    key: 'approvalCase',
    schema: 'chio.enterprise.approval-case.v1',
    rendererHint: 'enterprise-approval-case',
    label: 'enterprise approval case',
  },
  {
    key: 'controlEvidenceMap',
    schema: 'chio.enterprise.control-evidence-map.v1',
    rendererHint: 'enterprise-control-evidence-map',
    label: 'enterprise control evidence map',
  },
]

export const TRUST_MARKET_EVIDENCE_SPECS: readonly ProofRoomArtifactEvidenceSpec<ProofRoomTrustMarketEvidence>[] = [
  {
    key: 'discoverySnapshot',
    schema: 'chio.commerce.provider-discovery-snapshot.v1',
    rendererHint: 'provider-discovery-snapshot',
    label: 'provider discovery snapshot',
  },
  {
    key: 'providerSelection',
    schema: 'chio.commerce.provider-selection-report.v1',
    rendererHint: 'provider-selection-report',
    label: 'provider selection report',
  },
  {
    key: 'scorecard',
    schema: 'chio.trust.scorecard-snapshot.v1',
    rendererHint: 'trust-scorecard-snapshot',
    label: 'trust scorecard snapshot',
  },
  {
    key: 'reputationImport',
    schema: 'chio.trust.reputation-import-report.v1',
    rendererHint: 'reputation-import-report',
    label: 'reputation import report',
  },
  {
    key: 'slaCommitment',
    schema: 'chio.commerce.sla-commitment.v1',
    rendererHint: 'sla-commitment',
    label: 'SLA commitment',
  },
  {
    key: 'slaPerformance',
    schema: 'chio.commerce.sla-performance-report.v1',
    rendererHint: 'sla-performance-report',
    label: 'SLA performance report',
  },
  {
    key: 'collateralPosition',
    schema: 'chio.risk.collateral-position-report.v1',
    rendererHint: 'collateral-position-report',
    label: 'collateral position report',
  },
  {
    key: 'guaranteeDecision',
    schema: 'chio.risk.guarantee-decision.v1',
    rendererHint: 'guarantee-decision',
    label: 'guarantee decision',
  },
  {
    key: 'jurisdictionReceipt',
    schema: 'chio.risk.adjudication-jurisdiction-receipt.v1',
    rendererHint: 'adjudication-jurisdiction-receipt',
    label: 'adjudication jurisdiction receipt',
  },
]
