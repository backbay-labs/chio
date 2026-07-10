import { type ChangeEvent, useEffect, useState } from 'react'
import {
  fetchProofRoomFixtureCatalog,
  fetchProofRoomFixtureBundle,
  fetchProofRoomFixtureVerifierReport,
  fetchProofRoomStaticBundle,
  readProofRoomBundleEvidence,
} from '../api'
import type {
  ProofRoomArtifactReader,
  ProofRoomArtifactSourceRef,
  ProofRoomDsseSignature,
} from '../proofRoomArtifactEvidence'
import {
  assertProofRoomBundleDsseSignature,
  assertProofRoomBundleRelativePath,
  assertProofRoomArtifactDigest,
  fetchProofRoomTrustedBundleSignerKeys,
  proofRoomArtifactReader,
  readProofRoomArtifactSourceText,
} from '../proofRoomArtifactEvidence'
import type {
  ProofRoomAgentWebProjection,
  ProofRoomAgentWebProjectionManifest,
  ProofRoomArtifactRef,
  ProofRoomBundleManifest,
  ProofRoomCanonicalVerifierReport,
  ProofRoomCommerceEvidence,
  ProofRoomCommerceEventLog,
  ProofRoomCryptoContextEvidence,
  ProofRoomDisclosureEvidence,
  ProofRoomEnterpriseEvidence,
  ProofRoomAvailableFixture,
  ProofRoomFixtureCatalog,
  ProofRoomManifestClaim,
  ProofRoomNegativeCase,
  ProofRoomPublicSettlementProofBundle,
  ProofRoomPublicSettlementVerifierReport,
  ProofRoomReceiptCoverage,
  ProofRoomRejectedCheck,
  ProofRoomReportVerdict,
  ProofRoomRiskComptrollerReport,
  ProofRoomRiskReserveLedgerEntry,
  ProofRoomRiskSanctionReserveLedgerEntry,
  ProofRoomRuntimeEvidence,
  ProofRoomSettlementAmount,
  ProofRoomStaticBundle,
  ProofRoomSwarmEvidence,
  ProofRoomTrustMarketEvidence,
  ProofRoomWorkflowPreflightEvidence,
} from '../types'

type ProofRoomState =
  | { status: 'loading' }
  | { status: 'loaded'; bundle: ProofRoomStaticBundle }
  | { status: 'error'; message: string }

type FixtureReportState =
  | { status: 'idle' }
  | { status: 'loading'; fixtureId: string; path: string }
  | {
      status: 'loaded'
      fixtureId: string
      path: string
      report: ProofRoomCanonicalVerifierReport
    }
  | { status: 'error'; fixtureId: string; path: string; message: string }

type UploadedProofRoomFile = File & { webkitRelativePath?: string }

function formatVerdict(verdict: ProofRoomReportVerdict | string): string {
  return verdict.charAt(0).toUpperCase() + verdict.slice(1)
}

function verdictClass(verdict: ProofRoomReportVerdict | string): string {
  return verdict === 'verified' || verdict === 'accepted'
    ? 'proof-room-verdict-verified'
    : 'proof-room-verdict-failed'
}

function primaryArtifacts(claims: ProofRoomManifestClaim[]): string[] {
  const artifacts = new Set<string>()
  for (const claim of claims) {
    for (const artifact of claim.required_artifacts) {
      artifacts.add(artifact)
    }
  }
  return Array.from(artifacts)
}

function primaryFixtureAsset(kind: string): { path: string; label: string } {
  if (kind === 'proof-room') {
    return { path: 'proof-room-bundle/manifest.json', label: 'Open bundle' }
  }
  if (kind === 'workflow-preflight') {
    return { path: 'preflight-plan.json', label: 'Open plan' }
  }
  return { path: 'transaction-passport.json', label: 'Open passport' }
}

function canRenderFixtureBundle(kind: string): boolean {
  return kind === 'proof-room' || kind === 'transaction-passport'
}

function hasStaticFixtureAssets(fixture: ProofRoomAvailableFixture): boolean {
  return fixture.verifier_report !== undefined || canRenderFixtureBundle(fixture.kind)
}

function proofRoomFilePath(file: UploadedProofRoomFile): string {
  return file.webkitRelativePath || file.name
}

function selectedBundleRootPrefix(manifestFile: UploadedProofRoomFile): string {
  const path = proofRoomFilePath(manifestFile)
  return path.endsWith('/manifest.json') ? path.slice(0, -'/manifest.json'.length) : ''
}

function proofRoomUploadPath(file: UploadedProofRoomFile, bundleRootPrefix: string): string {
  const path = proofRoomFilePath(file)
  const prefix = bundleRootPrefix ? `${bundleRootPrefix}/` : ''
  const relativePath = prefix && path.startsWith(prefix) ? path.slice(prefix.length) : path
  assertProofRoomBundleRelativePath(relativePath)
  return relativePath
}

function findProofRoomFile(files: UploadedProofRoomFile[], suffix: string): UploadedProofRoomFile | null {
  assertProofRoomBundleRelativePath(suffix)
  return files.find((file) => proofRoomFilePath(file) === suffix || proofRoomFilePath(file).endsWith(`/${suffix}`)) ?? null
}

function hasSelectedVerifierRoot(files: UploadedProofRoomFile[], path: string): boolean {
  assertProofRoomBundleRelativePath(path)
  const candidates = path.includes('/') ? [path] : [path, `roots/${path}`]
  return files.some((file) => {
    const uploadedPath = proofRoomFilePath(file)
    return candidates.some(
      (candidate) => uploadedPath === candidate || uploadedPath.endsWith(`/${candidate}`),
    )
  })
}

function assertSelectedManifestPath(path: string | undefined, label: string): void {
  if (path === undefined) {
    return
  }
  try {
    assertProofRoomBundleRelativePath(path)
  } catch {
    throw new Error(`${label} is unsafe`)
  }
}

function assertSelectedManifestPaths(manifest: ProofRoomBundleManifest): void {
  assertSelectedManifestPath(manifest.verifier_report_ref.path, 'selected verifier report path')
  assertSelectedManifestPath(
    manifest.proof_room_verifier_report_ref?.path,
    'selected load report path',
  )
  assertSelectedManifestPath(
    manifest.transaction_passport_ref?.path,
    'selected transaction passport path',
  )
  assertSelectedManifestPath(manifest.evidence_graph_ref?.path, 'selected evidence graph path')
  assertSelectedManifestPath(manifest.signature?.signature_ref, 'selected bundle signature path')

  for (const artifact of manifest.artifacts ?? []) {
    assertSelectedManifestPath(artifact.path, 'selected artifact path')
  }
  for (const claim of manifest.claims) {
    for (const artifactPath of claim.required_artifacts) {
      assertSelectedManifestPath(artifactPath, 'selected claim artifact path')
    }
    for (const sourcePath of claim.source_refs ?? []) {
      assertSelectedManifestPath(sourcePath, 'selected claim source path')
    }
  }
  for (const negativeCase of manifest.negative_cases) {
    assertSelectedManifestPath(negativeCase.path, 'selected negative case path')
  }
  for (const coverage of manifest.receipt_coverage ?? []) {
    assertSelectedManifestPath(coverage.artifact_path, 'selected receipt coverage path')
  }
  for (const artifact of manifest.advisory_artifacts ?? []) {
    assertSelectedManifestPath(artifact.path, 'selected advisory artifact path')
  }
  for (const artifact of manifest.excluded_artifacts ?? []) {
    assertSelectedManifestPath(artifact.path, 'selected excluded artifact path')
  }
}

function artifactRefMatches(left: ProofRoomArtifactRef, right: ProofRoomArtifactRef): boolean {
  return left.path === right.path && left.sha256 === right.sha256 && left.schema === right.schema
}

function hasNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

const proofRoomManifestVerifiedClaims = new Set([
  'claim.proof_room.verifier_report_bound',
  'claim.proof_room.allow_and_deny_visible',
  'claim.proof_room.receipt_coverage_matrix_bound',
  'claim.proof_room.authority_evidence_bound',
])

function verifierReportProvesRenderedClaim(bundle: ProofRoomStaticBundle, claimId: string): boolean {
  if ((bundle.verifierReport.verified_claims ?? []).includes(claimId)) {
    return true
  }
  if (proofRoomManifestVerifiedClaims.has(claimId)) {
    return true
  }
  if (claimId !== 'claim.transaction.passport_root_verified') {
    return false
  }

  const report = bundle.verifierReport
  return (
    report.schema === 'chio.transaction.verifier-report.v1'
    && report.verdict === 'verified'
    && hasNonEmptyString(report.passport_id)
    && hasNonEmptyString(report.passport_path)
    && hasNonEmptyString(report.evidence_graph_path)
    && hasNonEmptyString(report.verifier_policy_path)
  )
}

function assertRenderedClaimsBound(bundle: ProofRoomStaticBundle) {
  const claims = new Map(bundle.manifest.claims.map((claim) => [claim.claim_id, claim]))
  const renderedClaimIds = new Set<string>()
  for (const renderedClaim of bundle.loadReport.rendered_claims) {
    if (renderedClaimIds.has(renderedClaim.claim_id)) {
      throw new Error('selected load report renders the same claim more than once')
    }
    renderedClaimIds.add(renderedClaim.claim_id)
    const claim = claims.get(renderedClaim.claim_id)
    if (!claim) {
      throw new Error('selected load report renders a claim absent from the manifest')
    }
    const sourceIsVerifierReport = renderedClaim.source === bundle.manifest.verifier_report_ref.path
    const sourceIsRequiredArtifact = claim.required_artifacts.includes(renderedClaim.source)
    if (!sourceIsVerifierReport && !sourceIsRequiredArtifact) {
      throw new Error('selected load report renders a claim from unbacked evidence')
    }
    if (renderedClaim.verdict === 'verified' && !sourceIsRequiredArtifact) {
      throw new Error('selected load report verifies a claim from unbacked evidence')
    }
    if (renderedClaim.verdict === 'verified' && !verifierReportProvesRenderedClaim(bundle, renderedClaim.claim_id)) {
      throw new Error('selected load report verifies a claim absent from the verifier report')
    }
  }

  for (const claim of bundle.manifest.claims) {
    if (!renderedClaimIds.has(claim.claim_id)) {
      throw new Error('selected load report omits a manifest claim')
    }
  }
}

function assertManifestClaimsBacked(bundle: ProofRoomStaticBundle) {
  const manifestArtifactPaths = new Set<string>([
    bundle.manifest.verifier_report_ref.path,
  ])
  if (bundle.manifest.proof_room_verifier_report_ref?.path) {
    manifestArtifactPaths.add(bundle.manifest.proof_room_verifier_report_ref.path)
  }
  if (bundle.manifest.transaction_passport_ref?.path) {
    manifestArtifactPaths.add(bundle.manifest.transaction_passport_ref.path)
  }
  if (bundle.manifest.evidence_graph_ref?.path) {
    manifestArtifactPaths.add(bundle.manifest.evidence_graph_ref.path)
  }
  for (const artifact of bundle.manifest.artifacts ?? []) {
    manifestArtifactPaths.add(artifact.path)
  }

  for (const claim of bundle.manifest.claims) {
    for (const artifactPath of claim.required_artifacts) {
      assertProofRoomBundleRelativePath(artifactPath)
      if (!manifestArtifactPaths.has(artifactPath)) {
        throw new Error(
          `selected manifest claim references unmanifested artifact: ${artifactPath}`,
        )
      }
    }
  }
}

function negativeFailureCodeMatches(error: string, expectedCode: string): boolean {
  let index = error.indexOf(expectedCode)
  while (index >= 0) {
    const before = index === 0 ? undefined : error[index - 1]
    const afterIndex = index + expectedCode.length
    const after = afterIndex >= error.length ? undefined : error[afterIndex]
    const startMatches = before === undefined || before === ':' || /\s/.test(before)
    const endMatches = after === undefined || after === ':'
    if (startMatches && endMatches) {
      return true
    }
    index = error.indexOf(expectedCode, index + 1)
  }
  return false
}

function assertVerifiedNegativeCasesBound(bundle: ProofRoomStaticBundle) {
  if (bundle.loadReport.verdict !== 'verified') {
    return
  }

  const ids = new Set<string>()
  for (const negativeCase of bundle.manifest.negative_cases) {
    if (!negativeCase.id) {
      throw new Error('selected negative case id is missing')
    }
    if (ids.has(negativeCase.id)) {
      throw new Error('selected negative case id is duplicated')
    }
    ids.add(negativeCase.id)
    if (!negativeCase.path) {
      throw new Error(`selected negative case path is missing for ${negativeCase.id}`)
    }
    if (!negativeCase.expected_failure_code) {
      throw new Error(`selected negative case expected failure is missing for ${negativeCase.id}`)
    }
    if (!negativeCase.observed_failure_code) {
      throw new Error(`selected negative case observed failure is missing for ${negativeCase.id}`)
    }
    if (!negativeFailureCodeMatches(negativeCase.observed_failure_code, negativeCase.expected_failure_code)) {
      throw new Error(`selected negative case observed failure does not match expected failure for ${negativeCase.id}`)
    }
  }
}

function assertProofRoomBundle(bundle: ProofRoomStaticBundle): ProofRoomStaticBundle {
  if (bundle.manifest.schema !== 'chio.proof-room.bundle.v1') {
    throw new Error('selected manifest has unsupported Proof Room schema')
  }
  assertSelectedManifestPaths(bundle.manifest)
  if (bundle.loadReport.schema !== 'chio.proof-room.verifier-report.v1') {
    throw new Error('selected load report has unsupported Proof Room schema')
  }
  if (bundle.loadReport.bundle_id !== bundle.manifest.bundle_id) {
    throw new Error('selected load report bundle does not match the manifest')
  }
  if (bundle.loadReport.fixture_id !== bundle.manifest.fixture_id) {
    throw new Error('selected load report fixture does not match the manifest')
  }
  if (bundle.loadReport.ui_verdict_source !== 'verifier_report_ref') {
    throw new Error('selected load report verdict source is not the verifier report')
  }
  if (!artifactRefMatches(bundle.manifest.verifier_report_ref, bundle.loadReport.source_verifier_report_ref)) {
    throw new Error('selected load report is not bound to the manifest verifier report')
  }
  if (bundle.verifierReport.schema !== bundle.manifest.verifier_report_ref.schema) {
    throw new Error('selected verifier report has unsupported schema')
  }
  if (
    typeof bundle.verifierReport.verdict === 'string'
    && bundle.verifierReport.verdict !== bundle.loadReport.verdict
  ) {
    throw new Error('selected verifier report verdict does not match the load report')
  }
  assertVerifiedNegativeCasesBound(bundle)
  assertRenderedClaimsBound(bundle)
  return bundle
}

function requireSelectedVerifierRoots(files: UploadedProofRoomFile[], bundle: ProofRoomStaticBundle) {
  const requiredPaths = [
    bundle.verifierReport.passport_path,
    bundle.verifierReport.evidence_graph_path,
    bundle.verifierReport.verifier_policy_path,
  ]

  if (requiredPaths.some((path) => typeof path !== 'string' || path.length === 0)) {
    throw new Error('selected verifier report must name transaction passport verifier roots')
  }

  const missingPaths = requiredPaths.filter((path) => !hasSelectedVerifierRoot(files, path ?? ''))
  if (missingPaths.length > 0) {
    throw new Error(`selected files must include ${missingPaths.join(', ')}`)
  }
}

async function readFileText(file: File): Promise<string> {
  if ('text' in file && typeof file.text === 'function') {
    return file.text()
  }

  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.addEventListener('load', () => {
      resolve(String(reader.result ?? ''))
    })
    reader.addEventListener('error', () => {
      reject(reader.error ?? new Error('selected file could not be read'))
    })
    reader.readAsText(file)
  })
}

async function assertSelectedBundleSignature(
  files: UploadedProofRoomFile[],
  manifest: ProofRoomBundleManifest,
  manifestText: string,
) {
  if (!manifest.signature) {
    throw new Error('selected bundle signature missing')
  }
  if (manifest.signature.kind !== 'detached-dsse') {
    throw new Error('selected bundle signature kind is unsupported')
  }
  if (!manifest.signature.signature_ref) {
    throw new Error('selected bundle signature path is missing')
  }
  const signatureFile = findProofRoomFile(files, manifest.signature.signature_ref)
  if (!signatureFile) {
    throw new Error(`selected files must include ${manifest.signature.signature_ref}`)
  }

  const signatureText = await readFileText(signatureFile)
  const signature = JSON.parse(signatureText) as ProofRoomDsseSignature
  const trustedSignerKeys = await fetchProofRoomTrustedBundleSignerKeys('selected bundle signature')
  await assertProofRoomBundleDsseSignature(
    signature,
    manifestText,
    'selected bundle signature',
    trustedSignerKeys,
  )
}

async function readSelectedManifestArtifact(
  files: UploadedProofRoomFile[],
  artifact: ProofRoomArtifactRef,
  label: string,
): Promise<string> {
  return readProofRoomArtifactSourceText(artifact, label, (sourceArtifact) =>
    readSelectedManifestArtifactSource(files, sourceArtifact))
}

async function readSelectedManifestArtifactSource(
  files: UploadedProofRoomFile[],
  artifact: ProofRoomArtifactSourceRef,
): Promise<{ contents: string }> {
  const file = findProofRoomFile(files, artifact.path)
  if (!file) {
    throw new Error(`selected files must include ${artifact.path}`)
  }
  return { contents: await readFileText(file) }
}

async function assertSelectedManifestArtifactDigest(
  files: UploadedProofRoomFile[],
  artifact: ProofRoomArtifactRef | undefined,
  label: string,
): Promise<void> {
  if (!artifact) {
    return
  }
  await readSelectedManifestArtifact(files, artifact, label)
}

function selectedProofRoomArtifactReader(files: UploadedProofRoomFile[]): ProofRoomArtifactReader {
  return proofRoomArtifactReader((artifact: ProofRoomArtifactSourceRef) =>
    readSelectedManifestArtifactSource(files, artifact))
}

async function readSelectedProofRoomBundle(fileList: FileList | UploadedProofRoomFile[]): Promise<ProofRoomStaticBundle> {
  const files = Array.from(fileList) as UploadedProofRoomFile[]
  const manifestFile = findProofRoomFile(files, 'manifest.json')

  if (!manifestFile) {
    throw new Error('selected files must include manifest.json and load-report.json')
  }

  const manifestText = await readFileText(manifestFile)
  const manifest: ProofRoomBundleManifest = JSON.parse(manifestText)
  assertSelectedManifestPaths(manifest)
  const loadReportRef = manifest.proof_room_verifier_report_ref
  const loadReportFile = findProofRoomFile(
    files,
    loadReportRef?.path ?? 'ui/proof-room-static/load-report.json',
  ) ?? (loadReportRef ? null : findProofRoomFile(files, 'load-report.json'))

  if (!loadReportFile) {
    throw new Error('selected files must include manifest.json and load-report.json')
  }

  const verifierReportFile = findProofRoomFile(files, manifest.verifier_report_ref?.path ?? '')
  if (!verifierReportFile) {
    throw new Error('selected files must include the manifest verifier report')
  }
  const [loadReportText, verifierReportText] = await Promise.all([
    readFileText(loadReportFile),
    readFileText(verifierReportFile),
  ])
  const bundle = assertProofRoomBundle({
    manifest,
    loadReport: JSON.parse(loadReportText),
    verifierReport: JSON.parse(verifierReportText),
  })
  assertManifestClaimsBacked(bundle)
  await assertProofRoomArtifactDigest(
    verifierReportText,
    manifest.verifier_report_ref.sha256,
    'selected verifier report',
  )
  if (loadReportRef?.sha256) {
    await assertProofRoomArtifactDigest(
      loadReportText,
      loadReportRef.sha256,
      'selected load report',
    )
  }
  await Promise.all([
    assertSelectedManifestArtifactDigest(
      files,
      manifest.transaction_passport_ref,
      'selected transaction passport',
    ),
    assertSelectedManifestArtifactDigest(files, manifest.evidence_graph_ref, 'selected evidence graph'),
  ])
  const evidence = await readProofRoomBundleEvidence(
    manifest,
    bundle.verifierReport,
    'selected',
    selectedProofRoomArtifactReader(files),
  )
  requireSelectedVerifierRoots(files, bundle)
  await assertSelectedBundleSignature(files, manifest, manifestText)
  return {
    ...bundle,
    ...evidence,
  }
}

async function verifySelectedProofRoomBundleUpload(files: UploadedProofRoomFile[]) {
  const manifestFile = findProofRoomFile(files, 'manifest.json')
  if (!manifestFile) {
    throw new Error('selected files must include manifest.json and load-report.json')
  }

  const formData = new FormData()
  const bundleRootPrefix = selectedBundleRootPrefix(manifestFile)
  for (const file of files) {
    formData.append('file', file, proofRoomUploadPath(file, bundleRootPrefix))
  }

  const response = await fetch('/proof-room/upload/verify', {
    method: 'POST',
    body: formData,
  })
  const body = await response.json() as Record<string, unknown>
  if (
    !response.ok
    || body.schema !== 'chio.proof-room.upload-verification.v1'
    || body.verdict !== 'verified'
  ) {
    throw new Error(
      typeof body.error === 'string'
        ? body.error
        : 'selected Proof Room bundle server verification failed',
    )
  }
}

function NegativeCases({ cases }: { cases: ProofRoomNegativeCase[] }) {
  if (cases.length === 0) {
    return <p className="proof-room-muted">No negative cases in this fixture.</p>
  }

  return (
    <div className="proof-room-list">
      {cases.map((negativeCase) => (
        <div className="proof-room-row" key={negativeCase.id}>
          <div>
            <strong>{negativeCase.id}</strong>
            <span>{negativeCase.path}</span>
          </div>
          <div className="proof-room-negative-codes">
            <span>Expected</span>
            <code>{negativeCase.expected_failure_code}</code>
            {negativeCase.observed_failure_code ? (
              <>
                <span>Observed</span>
                <code>{negativeCase.observed_failure_code}</code>
              </>
            ) : null}
          </div>
        </div>
      ))}
    </div>
  )
}

function FixtureCatalog({
  catalog,
  onRenderFixture,
}: {
  catalog: ProofRoomFixtureCatalog | null
  onRenderFixture: (fixture: ProofRoomAvailableFixture) => void
}) {
  const [selectedReport, setSelectedReport] = useState<FixtureReportState>({ status: 'idle' })
  const availableFixtures = catalog?.available_fixtures ?? []
  if (!catalog || (catalog.fixtures.length === 0 && availableFixtures.length === 0)) {
    return null
  }

  async function inspectFixtureReport(fixtureId: string, path: string) {
    setSelectedReport({ status: 'loading', fixtureId, path })
    try {
      const report = await fetchProofRoomFixtureVerifierReport(path)
      setSelectedReport({ status: 'loaded', fixtureId, path, report })
    } catch (error: unknown) {
      setSelectedReport({
        status: 'error',
        fixtureId,
        path,
        message: error instanceof Error ? error.message : 'fixture verifier report failed',
      })
    }
  }

  return (
    <section className="proof-room-section">
      <h3>Fixture Catalog</h3>
      <div className="proof-room-list">
        {catalog.fixtures.map((fixture) => (
          <div className="proof-room-row" key={`${fixture.fixture_id}:${fixture.bundle_id}`}>
            <div>
              <strong>{fixture.fixture_id}</strong>
              <span>{fixture.bundle_id}</span>
              <span>{fixture.manifest_path}</span>
              <span>{fixture.load_report_path}</span>
            </div>
            <span className={`proof-room-verdict-chip ${verdictClass(fixture.verdict)}`}>
              {formatVerdict(fixture.verdict)}
            </span>
          </div>
        ))}
      </div>
      {availableFixtures.length > 0 ? (
        <div className="proof-room-list proof-room-available-fixtures">
          {availableFixtures.map((fixture) => {
            const reportPath = fixture.verifier_report.path
            const primaryAsset = primaryFixtureAsset(fixture.kind)
            const staticAssetsAvailable = hasStaticFixtureAssets(fixture)
            return (
              <div className="proof-room-row" key={fixture.id}>
                <div>
                  <strong>{fixture.id}</strong>
                  <span>{fixture.kind}</span>
                  <span>{fixture.description}</span>
                  <code>{fixture.path}</code>
                  <div className="proof-room-negative-codes">
                    <span>Status</span>
                    <code>{fixture.verifier_report.status}</code>
                    <span>Report</span>
                    <span
                      className={`proof-room-verdict-chip ${verdictClass(fixture.verifier_report.verdict)}`}
                    >
                      {formatVerdict(fixture.verifier_report.verdict)}
                    </span>
                    {fixture.verifier_report.failure_code ? (
                      <>
                        <span>Failure</span>
                        <code>{fixture.verifier_report.failure_code}</code>
                      </>
                    ) : null}
                    {fixture.verifier_report.error ? (
                      <span>{fixture.verifier_report.error}</span>
                    ) : null}
                  </div>
                  <a
                    className="proof-room-fixture-link"
                    href={reportPath}
                  >
                    Open report
                  </a>
                  <button
                    type="button"
                    className="proof-room-fixture-link proof-room-fixture-button"
                    onClick={() => {
                      void inspectFixtureReport(fixture.id, reportPath)
                    }}
                  >
                    Inspect report
                  </button>
                  {canRenderFixtureBundle(fixture.kind) ? (
                    <button
                      type="button"
                      className="proof-room-fixture-link proof-room-fixture-button"
                      onClick={() => {
                        onRenderFixture(fixture)
                      }}
                    >
                      Render fixture
                    </button>
                  ) : null}
                  {staticAssetsAvailable ? (
                    <a
                      className="proof-room-fixture-link"
                      href={`/proof-room-fixtures/${fixture.id}/${primaryAsset.path}`}
                    >
                      {primaryAsset.label}
                    </a>
                  ) : null}
                </div>
              </div>
            )
          })}
        </div>
      ) : null}
      <SelectedFixtureReport state={selectedReport} />
    </section>
  )
}

function SelectedFixtureReport({ state }: { state: FixtureReportState }) {
  if (state.status === 'idle') {
    return null
  }

  if (state.status === 'loading') {
    return (
      <div className="proof-room-panel proof-room-selected-fixture">
        <span className="operator-card-label">Selected Fixture Report</span>
        <strong>{state.fixtureId}</strong>
        <span>Loading {state.path}</span>
      </div>
    )
  }

  if (state.status === 'error') {
    return (
      <div className="proof-room-panel proof-room-selected-fixture">
        <span className="operator-card-label">Selected Fixture Report</span>
        <strong>{state.fixtureId}</strong>
        <span>{state.path}</span>
        <span>{state.message}</span>
      </div>
    )
  }

  const { report } = state
  const verifiedClaims = report.verified_claims ?? stringArrayField(report, 'verifiedClaims')
  const rejectedChecks = rejectedCheckArray(report, 'rejected_checks')
  return (
    <div className="proof-room-panel proof-room-selected-fixture">
      <span className="operator-card-label">Selected Fixture Report</span>
      <strong>{state.fixtureId}</strong>
      <span>{state.path}</span>
      <code>{report.schema}</code>
      {report.id ? <strong>{report.id}</strong> : null}
      {report.verdict ? (
        <span className={`proof-room-verdict-chip ${verdictClass(report.verdict)}`}>
          {formatVerdict(report.verdict)}
        </span>
      ) : null}
      {report.passport_id ? <span>{report.passport_id}</span> : null}
      {report.passport_path ? <span>{report.passport_path}</span> : null}
      {typeof report.evidence_class === 'string' ? <span>{report.evidence_class}</span> : null}
      {report.failure_code ? <code>{report.failure_code}</code> : null}
      {report.error ? <span>{report.error}</span> : null}
      {verifiedClaims.length > 0 ? (
        <div className="proof-room-artifacts">
          {verifiedClaims.map((claim) => (
            <code key={claim}>{claim}</code>
          ))}
        </div>
      ) : null}
      {rejectedChecks.length > 0 ? (
        <div className="proof-room-artifacts">
          <strong>Rejected checks</strong>
          {rejectedChecks.map((check, index) => (
            <div key={`${check.code ?? 'check'}-${check.task_id ?? index}`}>
              {check.code ? <code>{check.code}</code> : null}
              {check.message ? <span>{check.message}</span> : null}
              {check.task_id ? <span>{check.task_id}</span> : null}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  )
}

function rejectedCheckArray(
  source: Record<string, unknown>,
  field: string,
): ProofRoomRejectedCheck[] {
  const value = source[field]
  if (!Array.isArray(value)) {
    return []
  }
  return value.filter((entry): entry is ProofRoomRejectedCheck => isRejectedCheck(entry))
}

function isRejectedCheck(value: unknown): value is ProofRoomRejectedCheck {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false
  }
  const check = value as Record<string, unknown>
  return (
    optionalString(check.code) &&
    optionalString(check.message) &&
    optionalString(check.task_id)
  )
}

function optionalString(value: unknown): boolean {
  return value === undefined || typeof value === 'string'
}

function stringArrayField(source: Record<string, unknown>, field: string): string[] {
  const value = source[field]
  if (!Array.isArray(value)) {
    return []
  }
  return value.filter((entry): entry is string => typeof entry === 'string')
}

function ReceiptCoverage({ rows }: { rows: ProofRoomReceiptCoverage[] }) {
  if (rows.length === 0) {
    return <p className="proof-room-muted">No receipt coverage rows in this fixture.</p>
  }

  return (
    <div className="proof-room-table-wrap">
      <table className="receipt-table proof-room-table">
        <thead>
          <tr>
            <th>Category</th>
            <th>Status</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.category}>
              <td>{row.category}</td>
              <td>
                <span
                  className={`proof-room-verdict-chip ${
                    row.status === 'covered'
                      ? 'proof-room-verdict-verified'
                      : 'proof-room-verdict-excluded'
                  }`}
                >
                  {row.status}
                </span>
              </td>
              <td>
                {row.artifact_path ? <code>{row.artifact_path}</code> : null}
                {row.terminal_status ? <span>{row.terminal_status}</span> : null}
                {row.exclusion_reason ? <span>{row.exclusion_reason}</span> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function valueText(value: string | number | undefined): string {
  return value === undefined ? '' : String(value)
}

function booleanText(value: boolean | undefined): string {
  return value === undefined ? '' : String(value)
}

function RuntimeEnforcement({ evidence }: { evidence?: ProofRoomRuntimeEvidence }) {
  if (!evidence) {
    return null
  }

  const {
    executionLease,
    revocationFreshnessProof,
    sandboxAttestation,
    toolServerAck,
  } = evidence

  return (
    <section className="proof-room-section">
      <h3>Runtime Enforcement</h3>
      <div className="proof-room-grid">
        {executionLease ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Execution Lease</span>
            <strong>{executionLease.lease_id}</strong>
            <span>{executionLease.tool_server_id}</span>
            <span>{executionLease.tool_instance_id}</span>
            <code>{executionLease.side_effect_class}</code>
            <code>{executionLease.nonce}</code>
          </div>
        ) : null}
        {revocationFreshnessProof ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Revocation Freshness</span>
            <strong>{revocationFreshnessProof.proof_id}</strong>
            <span>{revocationFreshnessProof.oracle_id}</span>
            <span>{revocationFreshnessProof.epoch_id}</span>
            <code>sequence {valueText(revocationFreshnessProof.sequence)}</code>
            <code>revoked {booleanText(revocationFreshnessProof.revoked_leaf_result)}</code>
          </div>
        ) : null}
        {sandboxAttestation ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Sandbox Attestation</span>
            <strong>{sandboxAttestation.attestation_id}</strong>
            <span>{sandboxAttestation.tool_server_id}</span>
            <span>{sandboxAttestation.attester}</span>
            <code>{sandboxAttestation.sandbox_profile_digest}</code>
            <code>{sandboxAttestation.egress_policy_digest}</code>
          </div>
        ) : null}
        {toolServerAck ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Tool-Server Ack</span>
            <strong>{toolServerAck.ack_id}</strong>
            <span>{toolServerAck.terminal_status}</span>
            <span>{toolServerAck.lease_id}</span>
            <span>{toolServerAck.sandbox_attestation_ref}</span>
            <code>{toolServerAck.nonce}</code>
          </div>
        ) : null}
      </div>
      <div className="proof-room-table-wrap">
        <table className="receipt-table proof-room-table">
          <thead>
            <tr>
              <th>Binding</th>
              <th>Subject</th>
              <th>Digest Or Ref</th>
            </tr>
          </thead>
          <tbody>
            {executionLease ? (
              <tr>
                <td>Policy</td>
                <td>{executionLease.lease_id}</td>
                <td>{executionLease.policy_digest}</td>
              </tr>
            ) : null}
            {executionLease ? (
              <tr>
                <td>Request</td>
                <td>{executionLease.lease_id}</td>
                <td>{executionLease.request_digest}</td>
              </tr>
            ) : null}
            {sandboxAttestation ? (
              <tr>
                <td>Tool Manifest</td>
                <td>{sandboxAttestation.tool_instance_id}</td>
                <td>{sandboxAttestation.tool_manifest_digest}</td>
              </tr>
            ) : null}
            {revocationFreshnessProof ? (
              <tr>
                <td>Revocation Root</td>
                <td>{revocationFreshnessProof.epoch_id}</td>
                <td>{revocationFreshnessProof.epoch_root}</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function CryptoContext({ evidence }: { evidence?: ProofRoomCryptoContextEvidence }) {
  if (!evidence) {
    return null
  }

  const {
    verificationContext,
    keyState,
    revocationSnapshot,
    privacyProfile,
    transparencyProof,
    cryptoContextReport,
  } = evidence
  const activeKeyState = keyState ?? verificationContext?.key_state
  const activeRevocationSnapshot = revocationSnapshot ?? verificationContext?.revocation_snapshot
  const verifiedClaims = cryptoContextReport?.verified_claims ?? []
  const disclosedFields = cryptoContextReport?.disclosed_fields ?? []

  return (
    <section className="proof-room-section">
      <h3>Crypto Context</h3>
      <div className="proof-room-grid">
        {verificationContext ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Verification Context</span>
            <strong>{verificationContext.context_id}</strong>
            <span>{verificationContext.proof_mechanism}</span>
            <span>{verificationContext.audience}</span>
            <code>{verificationContext.algorithm}</code>
            <code>nonce {verificationContext.nonce_replay_status}</code>
          </div>
        ) : null}
        {activeKeyState ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Key State</span>
            <strong>{activeKeyState.key_ref}</strong>
            <span>{activeKeyState.status}</span>
            <code>epoch {valueText(activeKeyState.epoch)}</code>
          </div>
        ) : null}
        {activeRevocationSnapshot ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Revocation Snapshot</span>
            <strong>{activeRevocationSnapshot.snapshot_ref}</strong>
            <span>{activeRevocationSnapshot.status}</span>
            <code>expires {valueText(activeRevocationSnapshot.expires_at)}</code>
          </div>
        ) : null}
        {privacyProfile ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Privacy Profile</span>
            <strong>{privacyProfile.profile_id}</strong>
            <span>{privacyProfile.required_audience}</span>
            <span>{privacyProfile.required_holder_binding}</span>
            <code>{privacyProfile.nonce_policy}</code>
          </div>
        ) : null}
        {transparencyProof ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Transparency Proof</span>
            <strong>{transparencyProof.proof_id}</strong>
            <span>{transparencyProof.log_id}</span>
            <code>{transparencyProof.checkpoint}</code>
          </div>
        ) : null}
        {cryptoContextReport ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Verifier Report</span>
            <strong>{cryptoContextReport.id}</strong>
            <span>{cryptoContextReport.verdict}</span>
            <span>{cryptoContextReport.evidence_class}</span>
            <code>proof {booleanText(cryptoContextReport.cryptographic_proof_verified)}</code>
          </div>
        ) : null}
      </div>
      <div className="proof-room-table-wrap">
        <table className="receipt-table proof-room-table">
          <thead>
            <tr>
              <th>Check</th>
              <th>Expected</th>
              <th>Observed</th>
            </tr>
          </thead>
          <tbody>
            {privacyProfile ? (
              <tr>
                <td>Algorithms</td>
                <td>{listText(privacyProfile.allowed_algorithms)}</td>
                <td>{verificationContext?.algorithm}</td>
              </tr>
            ) : null}
            {privacyProfile ? (
              <tr>
                <td>Holder</td>
                <td>{privacyProfile.required_holder_binding}</td>
                <td>{verificationContext?.holder_binding_ref}</td>
              </tr>
            ) : null}
            {privacyProfile ? (
              <tr>
                <td>Transparency</td>
                <td>{privacyProfile.required_transparency_state}</td>
                <td>{verificationContext?.transparency_state}</td>
              </tr>
            ) : null}
            {transparencyProof ? (
              <tr>
                <td>Inclusion</td>
                <td>{transparencyProof.root_hash}</td>
                <td>{transparencyProof.leaf_hash}</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      {verifiedClaims.length > 0 || disclosedFields.length > 0 ? (
        <div className="proof-room-artifacts">
          {verifiedClaims.map((claim) => (
            <code key={`claim:${claim}`}>{claim}</code>
          ))}
          {disclosedFields.map((field) => (
            <code key={`field:${field}`}>{field}</code>
          ))}
        </div>
      ) : null}
    </section>
  )
}

function CommerceEventRows({ eventLog }: { eventLog?: ProofRoomCommerceEventLog }) {
  const rows = eventLog?.events ?? []
  if (rows.length === 0) {
    return <p className="proof-room-muted">No commerce replay events in this fixture.</p>
  }

  return (
    <div className="proof-room-table-wrap">
      <table className="receipt-table proof-room-table">
        <thead>
          <tr>
            <th>Transition</th>
            <th>State</th>
            <th>Authority</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.event_id ?? `${row.transition}:${row.next_state}`}>
              <td>{row.transition}</td>
              <td>
                {row.prior_state ? <span>{row.prior_state}</span> : null}
                {row.next_state ? <span>{row.next_state}</span> : null}
              </td>
              <td>{row.authority_receipt_ref}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function CommerceOrder({ evidence }: { evidence?: ProofRoomCommerceEvidence }) {
  if (!evidence) {
    return null
  }

  const { orderContext, paymentLifecycle, eventLog } = evidence
  return (
    <section className="proof-room-section">
      <h3>Commerce Order</h3>
      <div className="proof-room-grid">
        {orderContext ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Order Context</span>
            <strong>{orderContext.order_id}</strong>
            <span>{orderContext.current_state}</span>
            <span>{orderContext.merchant_subject}</span>
            <span>{orderContext.buyer_subject}</span>
            <code>
              {valueText(orderContext.quote_amount_minor)} {orderContext.quote_currency}
            </code>
          </div>
        ) : null}
        {paymentLifecycle ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Payment Lifecycle</span>
            <strong>{paymentLifecycle.payment_status}</strong>
            <span>{paymentLifecycle.psp}</span>
            <span>{paymentLifecycle.payment_intent_id}</span>
            <code>
              {valueText(paymentLifecycle.amount_minor)} {paymentLifecycle.currency}
            </code>
          </div>
        ) : null}
        {eventLog ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Replay Log</span>
            <strong>{eventLog.id}</strong>
            <span>{eventLog.order_id}</span>
            <code>{valueText(eventLog.events?.length)} transitions</code>
          </div>
        ) : null}
      </div>
      <CommerceEventRows eventLog={eventLog} />
    </section>
  )
}

function DisclosureLineage({ evidence }: { evidence?: ProofRoomDisclosureEvidence }) {
  if (!evidence) {
    return null
  }

  const { capsule, signedLineageSubgraph, leakageLedger } = evidence
  const disclosedFields = capsule?.disclosed_fields ?? []
  const hiddenPredicates = capsule?.hidden_predicates ?? []
  const lineageNodes = signedLineageSubgraph?.nodes ?? []
  const redactions = signedLineageSubgraph?.redactions ?? []
  const leakageEntries = leakageLedger?.entries ?? []

  return (
    <section className="proof-room-section">
      <h3>Disclosure Lineage</h3>
      <div className="proof-room-grid">
        {capsule ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Disclosure Capsule</span>
            <strong>{capsule.id}</strong>
            <span>{capsule.privacy_profile_ref}</span>
            <span>{capsule.lineage_subgraph_ref}</span>
            <span>{capsule.leakage_ledger_ref}</span>
          </div>
        ) : null}
        {signedLineageSubgraph ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Signed Lineage</span>
            <strong>{signedLineageSubgraph.id}</strong>
            <span>{signedLineageSubgraph.transaction_passport_ref}</span>
            <code>{signedLineageSubgraph.signature}</code>
          </div>
        ) : null}
        {leakageLedger ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Leakage Ledger</span>
            <strong>{leakageLedger.id}</strong>
            <span>{leakageLedger.privacy_profile_ref}</span>
            <code>{valueText(leakageEntries.length)} entries</code>
          </div>
        ) : null}
      </div>
      {disclosedFields.length > 0 || hiddenPredicates.length > 0 ? (
        <div className="proof-room-artifacts">
          {disclosedFields.map((field) => (
            <code key={`field:${field}`}>{field}</code>
          ))}
          {hiddenPredicates.map((predicate, index) => (
            <code key={`predicate:${hiddenPredicateKey(predicate, index)}`}>
              {hiddenPredicateLabel(predicate)}
            </code>
          ))}
        </div>
      ) : null}
      {lineageNodes.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Node</th>
                <th>Receipt</th>
                <th>Disclosure</th>
              </tr>
            </thead>
            <tbody>
              {lineageNodes.map((node) => (
                <tr key={node.id ?? node.receipt_ref}>
                  <td>{node.id}</td>
                  <td>{node.receipt_ref}</td>
                  <td>{node.disclosure_state}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {redactions.length > 0 ? (
        <div className="proof-room-artifacts">
          {redactions.map((redaction) => (
            <code key={`${redaction.node_id}:${redaction.reason}`}>
              {redaction.node_id} {redaction.reason}
            </code>
          ))}
        </div>
      ) : null}
      {leakageEntries.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Field</th>
                <th>Kind</th>
                <th>Profile</th>
              </tr>
            </thead>
            <tbody>
              {leakageEntries.map((entry) => (
                <tr key={`${entry.field}:${entry.leakage_kind}`}>
                  <td>{entry.field}</td>
                  <td>{entry.leakage_kind}</td>
                  <td>
                    <span>{entry.allowed_by_profile ? 'allowed' : 'blocked'}</span>
                    {entry.residual_inference_note ? (
                      <span>{entry.residual_inference_note}</span>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  )
}

function hiddenPredicateKey(predicate: unknown, index: number): string {
  if (typeof predicate === 'string') {
    return predicate
  }
  if (predicate && typeof predicate === 'object' && 'predicate_id' in predicate) {
    const predicateId = (predicate as { predicate_id?: unknown }).predicate_id
    if (typeof predicateId === 'string' && predicateId.length > 0) {
      return predicateId
    }
  }
  return String(index)
}

function hiddenPredicateLabel(predicate: unknown): string {
  if (typeof predicate === 'string') {
    return predicate
  }
  if (!predicate || typeof predicate !== 'object') {
    return 'unknown_predicate'
  }
  const typed = predicate as {
    predicate_id?: unknown
    operator?: unknown
    operand?: unknown
    unit?: unknown
  }
  const predicateId =
    typeof typed.predicate_id === 'string' ? typed.predicate_id : 'unknown_predicate'
  const operator = typeof typed.operator === 'string' ? typed.operator : ''
  const operand = typeof typed.operand === 'string' ? typed.operand : ''
  const unit = typeof typed.unit === 'string' ? typed.unit : ''
  return [predicateId, operator, operand, unit].filter(Boolean).join(' ')
}

function listText(values: string[] | undefined): string {
  return values && values.length > 0 ? values.join(', ') : 'none'
}

function SwarmAuthority({ evidence }: { evidence?: ProofRoomSwarmEvidence }) {
  if (!evidence) {
    return null
  }

  const {
    taskGraph,
    continuations = [],
    witnessChains = [],
    routePlans = [],
    joinReceipt,
    budgetPool,
    revocationEpoch,
  } = evidence
  const taskNodes = taskGraph?.nodes ?? []
  const joins = taskGraph?.joins ?? []
  const budgetAllocations = budgetPool?.allocations ?? []

  return (
    <section className="proof-room-section">
      <h3>Swarm Authority</h3>
      <div className="proof-room-grid">
        {taskGraph ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Task Graph</span>
            <strong>{taskGraph.graphId}</strong>
            <span>{taskGraph.rootTransactionRef}</span>
            <span>{taskGraph.plannerSubject}</span>
            <code>
              depth {valueText(taskGraph.maxDepth)} fanout {valueText(taskGraph.maxFanout)}
            </code>
            <code>{taskGraph.budgetPoolRef}</code>
            <code>{taskGraph.revocationEpochRef}</code>
          </div>
        ) : null}
        {joinReceipt ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Join Receipt</span>
            <strong>{joinReceipt.joinId}</strong>
            <span>{joinReceipt.joinPredicate}</span>
            <span>{joinReceipt.nextTaskId}</span>
            <code>{listText(joinReceipt.actualParentReceiptIds)}</code>
          </div>
        ) : null}
        {budgetPool ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Budget Pool</span>
            <strong>{budgetPool.poolId}</strong>
            <span>{budgetPool.graphId}</span>
            <code>
              {valueText(budgetPool.totalUnits)} {budgetPool.currency}
            </code>
          </div>
        ) : null}
        {revocationEpoch ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Revocation Epoch</span>
            <strong>{revocationEpoch.epochId}</strong>
            <code>{revocationEpoch.rootHash}</code>
            <span>subjects {listText(revocationEpoch.revokedSubjects)}</span>
            <span>tasks {listText(revocationEpoch.revokedTaskIds)}</span>
          </div>
        ) : null}
      </div>
      {taskNodes.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Task</th>
                <th>Parent</th>
                <th>Route</th>
                <th>Continuation</th>
                <th>Budget</th>
                <th>Depth</th>
              </tr>
            </thead>
            <tbody>
              {taskNodes.map((node) => (
                <tr key={node.taskId ?? `${node.parentTaskId}:${node.depth}`}>
                  <td>{node.taskId}</td>
                  <td>{node.parentTaskId}</td>
                  <td>{node.routePlanRef}</td>
                  <td>{node.continuationTokenRef}</td>
                  <td>{node.budgetAllocationRef}</td>
                  <td>{valueText(node.depth)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {continuations.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Continuation</th>
                <th>Child</th>
                <th>Parent</th>
                <th>Route</th>
                <th>Budget</th>
                <th>Mode</th>
              </tr>
            </thead>
            <tbody>
              {continuations.map((token) => (
                <tr key={token.tokenId ?? token.childTaskId}>
                  <td>{token.tokenId}</td>
                  <td>{token.childTaskId}</td>
                  <td>{token.parentTaskId}</td>
                  <td>{token.routePlanReceiptId}</td>
                  <td>{token.budgetAllocationId}</td>
                  <td>{token.mode}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {witnessChains.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Witness</th>
                <th>Task</th>
                <th>Rule</th>
                <th>Digest</th>
                <th>Signature</th>
              </tr>
            </thead>
            <tbody>
              {witnessChains.flatMap((chain) =>
                (chain.hops ?? []).map((hop, index) => (
                  <tr key={`${chain.chainId}:${hop.attenuationRuleId ?? index}`}>
                    <td>{chain.chainId}</td>
                    <td>{chain.childTaskId}</td>
                    <td>{hop.attenuationRuleId}</td>
                    <td>{hop.policyDigest}</td>
                    <td>{hop.witnessSignature}</td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
        </div>
      ) : null}
      {routePlans.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Route Plan</th>
                <th>Task</th>
                <th>Route</th>
                <th>Target</th>
                <th>Constraints</th>
                <th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {routePlans.map((route) => (
                <tr key={route.routePlanId ?? route.taskId}>
                  <td>{route.routePlanId}</td>
                  <td>{route.taskId}</td>
                  <td>{route.selectedRoute}</td>
                  <td>{route.protocolTarget}</td>
                  <td>{listText(route.egressConstraints)}</td>
                  <td>{route.attenuationDecision}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {joins.length > 0 ? (
        <div className="proof-room-artifacts">
          {joins.map((join) => (
            <code key={join.joinId ?? `${join.parentTaskIds?.join(':')}:${join.nextTaskId}`}>
              {join.joinId} {listText(join.parentTaskIds)} {join.nextTaskId}
            </code>
          ))}
        </div>
      ) : null}
      {budgetAllocations.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Allocation</th>
                <th>Task</th>
                <th>Limit</th>
              </tr>
            </thead>
            <tbody>
              {budgetAllocations.map((allocation) => (
                <tr key={allocation.allocationId ?? allocation.taskId}>
                  <td>{allocation.allocationId}</td>
                  <td>{allocation.taskId}</td>
                  <td>
                    {valueText(allocation.maxUnits)} {budgetPool?.currency}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  )
}

function WorkflowPreflight({ evidence }: { evidence?: ProofRoomWorkflowPreflightEvidence }) {
  if (!evidence) {
    return null
  }

  const { plan, report } = evidence
  const childTasks = plan?.child_tasks ?? []
  const routePlans = plan?.route_plans ?? []
  const approvals = plan?.approvals ?? []
  const planningArtifacts = plan?.planning_artifacts ?? []
  const rejectedChecks = report?.rejected_checks ?? []
  const verifiedClaims = report?.verified_claims ?? []
  const liveAuthorityClaims = report?.live_authority_claims ?? []

  return (
    <section className="proof-room-section">
      <h3>Workflow Preflight</h3>
      <div className="proof-room-grid">
        {plan ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Plan</span>
            <strong>{plan.id}</strong>
            <span>{plan.issued_at}</span>
            <span>{plan.parent_task?.task_id}</span>
            <code>
              {valueText(plan.parent_task?.scope?.budget_minor)} {plan.parent_task?.scope?.currency}
            </code>
          </div>
        ) : null}
        {report ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Planning Evidence</span>
            <strong>{formatVerdict(report.verdict ?? '')}</strong>
            <span>{report.plan_id}</span>
            <span>{report.evidence_class}</span>
            <code>live authority claims {listText(liveAuthorityClaims)}</code>
          </div>
        ) : null}
        {plan?.budget_pool ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Budget Pool</span>
            <strong>{valueText(plan.budget_pool.total_minor)} {plan.budget_pool.currency}</strong>
          </div>
        ) : null}
        {plan?.revocation ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Revocation</span>
            <strong>{plan.revocation.epoch_id}</strong>
            <span>{plan.revocation.status}</span>
            <code>{plan.revocation.root_sha256}</code>
          </div>
        ) : null}
      </div>
      {childTasks.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Child Task</th>
                <th>Parent</th>
                <th>Actions</th>
                <th>Resources</th>
                <th>Budget</th>
              </tr>
            </thead>
            <tbody>
              {childTasks.map((task) => (
                <tr key={task.task_id ?? task.parent_task_id}>
                  <td>{task.task_id}</td>
                  <td>{task.parent_task_id}</td>
                  <td>{listText(task.requested_scope?.actions)}</td>
                  <td>{listText(task.requested_scope?.resources)}</td>
                  <td>
                    {valueText(task.requested_scope?.budget_minor)} {task.requested_scope?.currency}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {routePlans.length > 0 || approvals.length > 0 ? (
        <div className="proof-room-artifacts">
          {routePlans.map((route) => (
            <code key={route.route_ref}>
              {route.route_ref} {route.supported ? 'supported' : 'unsupported'}
            </code>
          ))}
          {approvals.map((approval) => (
            <code key={approval.approval_ref}>
              {approval.approval_ref} {approval.status}
            </code>
          ))}
        </div>
      ) : null}
      {plan?.registry_support?.supported_schemas?.length ? (
        <div className="proof-room-artifacts">
          {plan.registry_support.supported_schemas.map((schema) => (
            <code key={schema}>{schema}</code>
          ))}
        </div>
      ) : null}
      {planningArtifacts.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Planning Artifact</th>
                <th>Class</th>
                <th>Satisfies Claims</th>
              </tr>
            </thead>
            <tbody>
              {planningArtifacts.map((artifact) => (
                <tr key={artifact.artifact_ref ?? artifact.artifact_class}>
                  <td>{artifact.artifact_ref}</td>
                  <td>{artifact.artifact_class}</td>
                  <td>{listText(artifact.satisfies_claims)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {verifiedClaims.length > 0 ? (
        <div className="proof-room-artifacts">
          {verifiedClaims.map((claim) => (
            <code key={claim}>{claim}</code>
          ))}
        </div>
      ) : null}
      {rejectedChecks.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Rejected Check</th>
                <th>Task</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {rejectedChecks.map((check) => (
                <tr key={`${check.code}:${check.task_id}`}>
                  <td>{check.code}</td>
                  <td>{check.task_id}</td>
                  <td>{check.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  )
}

function EnterpriseExport({ evidence }: { evidence?: ProofRoomEnterpriseEvidence }) {
  if (!evidence) {
    return null
  }

  const {
    exportBundle,
    dataGovernanceReport,
    telemetryProjection,
    approvalCase,
    controlEvidenceMap,
  } = evidence
  const exportArtifacts = exportBundle?.artifacts ?? []
  const fieldClassifications = dataGovernanceReport?.field_classifications ?? []
  const telemetryEvents = telemetryProjection?.events ?? []
  const controls = controlEvidenceMap?.controls ?? []

  return (
    <section className="proof-room-section">
      <h3>Enterprise Export</h3>
      <div className="proof-room-grid">
        {exportBundle ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Export Bundle</span>
            <strong>{exportBundle.id}</strong>
            <span>{exportBundle.passport_id}</span>
            <span>{exportBundle.risk_comptroller_report_ref}</span>
            <span>{exportBundle.approval_case_ref}</span>
            <code>{exportBundle.bundle_digest}</code>
          </div>
        ) : null}
        {dataGovernanceReport ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Data Governance</span>
            <strong>{dataGovernanceReport.id}</strong>
            <span>{dataGovernanceReport.observed_region}</span>
            <span>{listText(dataGovernanceReport.allowed_regions)}</span>
            <code>{dataGovernanceReport.retention_class}</code>
            <code>{dataGovernanceReport.legal_hold_status}</code>
            <span>{dataGovernanceReport.redaction_profile_ref}</span>
          </div>
        ) : null}
        {approvalCase ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Approval Case</span>
            <strong>{approvalCase.id}</strong>
            <span>{approvalCase.decision}</span>
            <span>{approvalCase.decision_subject}</span>
            <code>quorum {valueText(approvalCase.required_quorum)}</code>
            <code>{approvalCase.expires_at}</code>
          </div>
        ) : null}
        {telemetryProjection ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Telemetry Projection</span>
            <strong>{telemetryProjection.id}</strong>
            <span>{telemetryProjection.passport_id}</span>
            <code>{valueText(telemetryEvents.length)} events</code>
          </div>
        ) : null}
        {controlEvidenceMap ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Control Map</span>
            <strong>{controlEvidenceMap.id}</strong>
            <span>{controlEvidenceMap.passport_id}</span>
            <code>{valueText(controls.length)} controls</code>
          </div>
        ) : null}
      </div>
      {approvalCase?.approvers?.length ? (
        <div className="proof-room-artifacts">
          {approvalCase.approvers.map((approver) => (
            <code key={approver}>{approver}</code>
          ))}
        </div>
      ) : null}
      {exportArtifacts.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Role</th>
                <th>Path</th>
                <th>Digest</th>
              </tr>
            </thead>
            <tbody>
              {exportArtifacts.map((artifact) => (
                <tr key={`${artifact.role}:${artifact.path}`}>
                  <td>{artifact.role}</td>
                  <td>{artifact.path}</td>
                  <td>{artifact.sha256}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {fieldClassifications.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Field</th>
                <th>Class</th>
                <th>Export Action</th>
              </tr>
            </thead>
            <tbody>
              {fieldClassifications.map((field) => (
                <tr key={`${field.field}:${field.export_action}`}>
                  <td>{field.field}</td>
                  <td>{field.classification}</td>
                  <td>{field.export_action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {telemetryEvents.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Event</th>
                <th>Kind</th>
                <th>Artifact</th>
                <th>Digest</th>
              </tr>
            </thead>
            <tbody>
              {telemetryEvents.map((event) => (
                <tr key={event.event_id ?? `${event.event_kind}:${event.artifact_ref}`}>
                  <td>{event.event_id}</td>
                  <td>{event.event_kind}</td>
                  <td>{event.artifact_ref}</td>
                  <td>{event.artifact_sha256}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {controls.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Control</th>
                <th>Family</th>
                <th>Claim</th>
                <th>Gate</th>
              </tr>
            </thead>
            <tbody>
              {controls.map((control) => (
                <tr key={control.control_id ?? control.claim_ref}>
                  <td>{control.control_id}</td>
                  <td>{control.control_family}</td>
                  <td>{control.claim_ref}</td>
                  <td>{control.gate_ref}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  )
}

function metricText(value: number | undefined, unit: string | undefined): string {
  return `${valueText(value)} ${unit ?? ''}`.trim()
}

function TrustMarketContext({ evidence }: { evidence?: ProofRoomTrustMarketEvidence }) {
  if (!evidence) {
    return null
  }

  const {
    discoverySnapshot,
    providerSelection,
    scorecard,
    reputationImport,
    slaCommitment,
    slaPerformance,
    collateralPosition,
    guaranteeDecision,
    jurisdictionReceipt,
  } = evidence
  const candidates = discoverySnapshot?.provider_candidates ?? []
  const rankings = providerSelection?.ranking_results ?? []
  const scoreComponents = scorecard?.component_scores ?? []
  const slaMetrics = slaCommitment?.metric_definitions ?? []
  const performanceMetrics = slaPerformance?.computed_metric_results ?? []

  return (
    <section className="proof-room-section">
      <h3>Trust Market Context</h3>
      <div className="proof-room-grid">
        {discoverySnapshot ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Provider Discovery</span>
            <strong>{discoverySnapshot.id}</strong>
            <span>{discoverySnapshot.market_scope}</span>
            <span>{discoverySnapshot.discovery_authority_ref}</span>
            <code>{valueText(candidates.length)} candidates</code>
          </div>
        ) : null}
        {providerSelection ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Provider Selection</span>
            <strong>{providerSelection.selected_provider_subject}</strong>
            <span>{providerSelection.id}</span>
            <span>{providerSelection.discovery_snapshot_ref}</span>
            <code>{listText(providerSelection.selection_reason_codes)}</code>
          </div>
        ) : null}
        {scorecard ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Local Scorecard</span>
            <strong>{valueText(scorecard.computed_score)}</strong>
            <span>{scorecard.subject}</span>
            <span>{scorecard.scope}</span>
            <code>{listText(scorecard.downgrade_reasons)}</code>
          </div>
        ) : null}
        {reputationImport ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Reputation Import</span>
            <strong>{reputationImport.id}</strong>
            <span>{reputationImport.source_network}</span>
            <span>{reputationImport.issuer}</span>
            <code>{reputationImport.import_verdict}</code>
          </div>
        ) : null}
        {slaCommitment ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">SLA Commitment</span>
            <strong>{slaCommitment.id}</strong>
            <span>{slaCommitment.service_scope}</span>
            <span>{slaCommitment.collateral_position_ref}</span>
            <span>{slaCommitment.guarantee_decision_ref}</span>
          </div>
        ) : null}
        {slaPerformance ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">SLA Performance</span>
            <strong>{slaPerformance.id}</strong>
            <span>{slaPerformance.breach_verdict}</span>
            <span>{slaPerformance.sla_ref}</span>
          </div>
        ) : null}
        {collateralPosition ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Collateral</span>
            <strong>{collateralPosition.id}</strong>
            <span>{collateralPosition.source_type}</span>
            <code>
              {valueText(collateralPosition.available_amount)} {collateralPosition.currency_or_asset}
            </code>
          </div>
        ) : null}
        {guaranteeDecision ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Guarantee</span>
            <strong>{guaranteeDecision.id}</strong>
            <span>{guaranteeDecision.verdict}</span>
            <span>{guaranteeDecision.guarantee_type}</span>
            <code>
              {valueText(guaranteeDecision.maximum_remedy)} {guaranteeDecision.currency}
            </code>
          </div>
        ) : null}
        {jurisdictionReceipt ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Jurisdiction</span>
            <strong>{jurisdictionReceipt.jurisdiction_id}</strong>
            <span>{jurisdictionReceipt.policy_ref}</span>
            <code>{listText(jurisdictionReceipt.covered_dispute_types)}</code>
          </div>
        ) : null}
      </div>
      {candidates.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Candidate</th>
                <th>Jurisdiction</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {candidates.map((candidate) => (
                <tr key={candidate.subject ?? candidate.jurisdiction_ref}>
                  <td>{candidate.subject}</td>
                  <td>{candidate.jurisdiction_ref}</td>
                  <td>{candidate.excluded ? 'excluded' : 'available'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {rankings.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Provider</th>
                <th>Rank</th>
                <th>Score</th>
              </tr>
            </thead>
            <tbody>
              {rankings.map((ranking) => (
                <tr key={ranking.provider_subject ?? valueText(ranking.rank)}>
                  <td>{ranking.provider_subject}</td>
                  <td>{valueText(ranking.rank)}</td>
                  <td>{valueText(ranking.total_score)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {scoreComponents.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Score Component</th>
                <th>Score</th>
                <th>Weight</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {scoreComponents.map((component) => (
                <tr key={component.component ?? component.evidence_ref}>
                  <td>{component.component}</td>
                  <td>{valueText(component.score)}</td>
                  <td>{valueText(component.weight)}</td>
                  <td>{component.evidence_ref}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {slaMetrics.length > 0 || performanceMetrics.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Metric</th>
                <th>Target</th>
                <th>Observed</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {slaMetrics.map((metric) => {
                const observed = performanceMetrics.find(
                  (result) => result.metric === metric.metric,
                )
                return (
                  <tr key={metric.metric}>
                    <td>{metric.metric}</td>
                    <td>{metricText(metric.target, metric.unit)}</td>
                    <td>{metricText(observed?.value, observed?.unit)}</td>
                    <td>{observed?.passed ? 'passed' : ''}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : null}
      {guaranteeDecision?.backing_refs?.length || jurisdictionReceipt?.adjudicator_subjects?.length ? (
        <div className="proof-room-artifacts">
          {guaranteeDecision?.backing_refs?.map((ref) => (
            <code key={`backing:${ref}`}>{ref}</code>
          ))}
          {jurisdictionReceipt?.adjudicator_subjects?.map((subject) => (
            <code key={`adjudicator:${subject}`}>{subject}</code>
          ))}
          {jurisdictionReceipt?.slash_authority_refs?.map((subject) => (
            <code key={`slash:${subject}`}>{subject}</code>
          ))}
        </div>
      ) : null}
    </section>
  )
}

function amountText(amount: ProofRoomSettlementAmount | undefined): string {
  if (!amount) {
    return ''
  }
  return `${valueText(amount.units)} ${amount.currency ?? ''}`.trim()
}

function settlementFinalityText(
  observedConfirmations: number | undefined,
  requiredConfirmations: number | undefined,
): string {
  const observed = valueText(observedConfirmations)
  const required = valueText(requiredConfirmations)
  if (!observed && !required) {
    return ''
  }
  return `${observed || '0'} of ${required || '0'} confirmations`
}

function settlementChainText(
  chainId: string | undefined,
  blockNumber: number | undefined,
  registryRoot: string | undefined,
): string {
  return [
    chainId,
    blockNumber === undefined ? undefined : `block ${blockNumber}`,
    registryRoot,
  ].filter(hasNonEmptyString).join(' ')
}

function PublicSettlement({
  proof,
  verifierReport,
}: {
  proof?: ProofRoomPublicSettlementProofBundle
  verifierReport?: ProofRoomPublicSettlementVerifierReport
}) {
  if (!proof && !verifierReport) {
    return null
  }

  const receipt = proof?.settlement_receipt
  const chain = proof?.chain_snapshot
  const escrow = chain?.escrow
  const bond = chain?.bond
  const dispute = proof?.dispute_snapshot
  const finality = verifierReport?.finality_decision
  const witness = verifierReport?.public_witness
  const verifiedChain = verifierReport?.chain_context
  const comparisonRows = [
    {
      label: 'Verified finality',
      verified: settlementFinalityText(
        finality?.observed_confirmations,
        finality?.required_confirmations,
      ),
      supplied: settlementFinalityText(
        proof?.observed_confirmations,
        proof?.required_confirmations,
      ),
      suppliedLabel: 'Supplied finality',
    },
    {
      label: 'Verified chain',
      verified: settlementChainText(
        verifiedChain?.chain_id,
        verifiedChain?.observed_block_number,
        verifiedChain?.registry_root,
      ),
      supplied: settlementChainText(
        proof?.chain_id,
        chain?.observed_block_number,
        chain?.registry_root,
      ),
      suppliedLabel: 'Supplied chain',
    },
    {
      label: 'Verified settlement reference',
      verified: verifiedChain?.settlement_reference ?? '',
      supplied: receipt?.settlement_reference ?? '',
      suppliedLabel: 'Supplied settlement reference',
    },
    {
      label: 'Verified settlement state',
      verified: verifierReport?.recomputed_settlement_state ?? '',
      supplied: receipt?.lifecycle_state ?? '',
      suppliedLabel: 'Supplied settlement state',
    },
  ].filter((row) => row.verified || row.supplied)

  return (
    <section className="proof-room-section">
      <h3>Public Settlement</h3>
      {comparisonRows.length > 0 ? (
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Verifier Check</th>
                <th>Verified</th>
                <th>Supplied</th>
              </tr>
            </thead>
            <tbody>
              {comparisonRows.map((row) => (
                <tr key={row.label}>
                  <td>{row.label}</td>
                  <td>{row.verified}</td>
                  <td>
                    <span>{row.suppliedLabel}</span>
                    {row.supplied ? <code>{row.supplied}</code> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <div className="proof-room-grid">
        {finality ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Verifier Finality</span>
            <strong>{finality.status}</strong>
            {verifierReport?.recomputed_settlement_state ? (
              <span>{verifierReport.recomputed_settlement_state}</span>
            ) : null}
            <code>
              {valueText(finality.observed_confirmations)} of {valueText(finality.required_confirmations)} confirmations
            </code>
          </div>
        ) : null}
        {witness ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Public Witness</span>
            <strong>{witness.mode}</strong>
            {witness.witness_id ? <span>{witness.witness_id}</span> : null}
            {witness.body_hash ? <code>{witness.body_hash}</code> : null}
          </div>
        ) : null}
        {verifiedChain ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Verified Chain Context</span>
            <strong>{verifiedChain.settlement_path}</strong>
            <span>{verifiedChain.settlement_reference}</span>
            <span>{verifiedChain.chain_id}</span>
            {verifiedChain.settlement_tx_hash ? <code>{verifiedChain.settlement_tx_hash}</code> : null}
          </div>
        ) : null}
        {proof ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Proof Bundle</span>
            <strong>{proof.bundle_id}</strong>
            <span>{proof.commerce_order_id}</span>
            <span>{proof.chain_id}</span>
            <code>
              {valueText(proof.observed_confirmations)} of {valueText(proof.required_confirmations)} confirmations
            </code>
          </div>
        ) : null}
        {receipt ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Settlement Receipt</span>
            <strong>{receipt.lifecycle_state}</strong>
            <span>{receipt.settlement_reference}</span>
            <span>{receipt.execution_receipt_id}</span>
            <code>{amountText(receipt.settled_amount)}</code>
            {receipt.observed_execution?.externalReferenceId ? (
              <code>{receipt.observed_execution.externalReferenceId}</code>
            ) : null}
          </div>
        ) : null}
        {escrow ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Escrow</span>
            <strong>{escrow.escrow_id}</strong>
            <span>{escrow.escrow_contract}</span>
            <span>{escrow.beneficiary_address}</span>
            <code>locked {amountText(escrow.locked_amount)}</code>
            <code>released {amountText(escrow.released_amount)}</code>
          </div>
        ) : null}
        {chain ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Chain Snapshot</span>
            <strong>{valueText(chain.observed_block_number)}</strong>
            <span>{valueText(chain.latest_block_number)}</span>
            <code>{chain.registry_root}</code>
          </div>
        ) : null}
        {bond ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Bond</span>
            <strong>{bond.bond_vault_contract}</strong>
            <code>posted {amountText(bond.posted_amount)}</code>
            <code>minimum {amountText(bond.minimum_required_amount)}</code>
          </div>
        ) : null}
        <div className="proof-room-panel">
          <span className="operator-card-label">Dispute</span>
          <strong>{dispute?.posture ?? verifierReport?.dispute_context?.posture ?? proof?.dispute_posture}</strong>
          {dispute?.dispute_id ? <span>{dispute.dispute_id}</span> : null}
          <code>
            {valueText(dispute?.open_dispute_count ?? verifierReport?.dispute_context?.open_dispute_count)} open disputes
          </code>
        </div>
        {receipt?.oracle_evidence ? (
          <div className="proof-room-panel">
            <span className="operator-card-label">Oracle Evidence</span>
            <strong>{receipt.oracle_evidence.source}</strong>
            <span>{receipt.oracle_evidence.base}</span>
            <span>{receipt.oracle_evidence.quote}</span>
          </div>
        ) : null}
      </div>
    </section>
  )
}

function RiskLedgerRows({ rows }: { rows: ProofRoomRiskReserveLedgerEntry[] }) {
  if (rows.length === 0) {
    return <p className="proof-room-muted">No reserve ledger rows in this fixture.</p>
  }

  return (
    <div className="proof-room-table-wrap">
      <table className="receipt-table proof-room-table">
        <thead>
          <tr>
            <th>Lane</th>
            <th>Receipt</th>
            <th>Reserve</th>
            <th>Units</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.entry_id ?? `${row.lane}:${row.receipt_ref}`}>
              <td>{row.lane}</td>
              <td>{row.receipt_ref}</td>
              <td>{row.reserve_ref}</td>
              <td>{valueText(row.units)} {row.currency}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function RiskSanctionLedgerRows({ rows }: { rows: ProofRoomRiskSanctionReserveLedgerEntry[] }) {
  if (rows.length === 0) {
    return null
  }

  return (
    <>
      <h4>Sanction Reserve Ledger</h4>
      <div className="proof-room-table-wrap">
        <table className="receipt-table proof-room-table">
          <thead>
            <tr>
              <th>Lane</th>
              <th>Bridge</th>
              <th>Receipt</th>
              <th>Reserve</th>
              <th>Jurisdiction</th>
              <th>Units</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.entry_id ?? `${row.bridge_id}:${row.receipt_ref}`}>
                <td>{row.lane}</td>
                <td>{row.bridge_id}</td>
                <td>{row.receipt_ref}</td>
                <td>{row.reserve_ref}</td>
                <td>{row.jurisdiction_ref}</td>
                <td>{valueText(row.units)} {row.currency}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

function RiskComptroller({ report }: { report?: ProofRoomRiskComptrollerReport }) {
  if (!report) {
    return null
  }

  const { facility, coverage, reconciliation } = report
  const ledger = report.reserve_ledger ?? []
  const sanctionLedger = report.sanction_reserve_ledger ?? []

  return (
    <section className="proof-room-section">
      <h3>Risk Comptroller</h3>
      <div className="proof-room-grid">
        <div className="proof-room-panel">
          <span className="operator-card-label">Facility</span>
          <strong>{facility?.facility_id}</strong>
          <span>{facility?.state}</span>
          <span>{facility?.reserve_ref}</span>
          <code>{valueText(facility?.reserve_units)} {facility?.reserve_currency}</code>
        </div>
        <div className="proof-room-panel">
          <span className="operator-card-label">Coverage</span>
          <strong>{coverage?.coverage_id}</strong>
          <span>{coverage?.status}</span>
          <span>{coverage?.order_id}</span>
          <code>{valueText(coverage?.exposure_units)} {coverage?.currency}</code>
        </div>
        <div className="proof-room-panel">
          <span className="operator-card-label">Reconciliation</span>
          <strong>{reconciliation?.status}</strong>
          <span>{reconciliation?.order_id}</span>
          <code>reserve {valueText(reconciliation?.reserve_units)} {reconciliation?.currency}</code>
          <code>consumed {valueText(reconciliation?.consumed_reserve_units)} {reconciliation?.currency}</code>
        </div>
      </div>
      <RiskLedgerRows rows={ledger} />
      <RiskSanctionLedgerRows rows={sanctionLedger} />
    </section>
  )
}

function AgentWebClaimList({ claims }: { claims: string[] }) {
  if (claims.length === 0) {
    return <p className="proof-room-muted">No unsupported external authority claims listed.</p>
  }

  return (
    <div className="proof-room-artifacts">
      {claims.map((claim) => (
        <code key={claim}>{claim}</code>
      ))}
    </div>
  )
}

function agentWebUnsupportedClaims(
  projectionManifest: ProofRoomAgentWebProjectionManifest | undefined,
): string[] {
  return projectionManifest?.unsupported_claims ?? []
}

function AgentWebProjections({ projections }: { projections: ProofRoomAgentWebProjection[] }) {
  if (projections.length === 0) {
    return null
  }

  return (
    <section className="proof-room-section">
      <h3>Agent Web</h3>
      <div className="proof-room-list">
        {projections.map(({ envelope, projectionManifest }) => (
          <div
            className="proof-room-row"
            key={envelope.envelope_id ?? `${envelope.source_protocol}:${envelope.external_subject}`}
          >
            <div>
              <strong>{envelope.envelope_id}</strong>
              <span>{envelope.source_protocol} {envelope.source_protocol_version}</span>
              <span>{envelope.external_subject}</span>
              <span>{envelope.external_subject_path}</span>
              <code>{envelope.external_subject_digest}</code>
              {envelope.receipt_refs?.map((receiptRef) => (
                <span key={receiptRef}>{receiptRef}</span>
              ))}
              {envelope.limitations?.map((limitation) => (
                <span key={limitation}>{limitation}</span>
              ))}
              {projectionManifest?.copy_limitations?.map((limitation) => (
                <span key={limitation}>{limitation}</span>
              ))}
            </div>
            <AgentWebClaimList claims={agentWebUnsupportedClaims(projectionManifest)} />
          </div>
        ))}
      </div>
    </section>
  )
}

export function ProofRoomView() {
  const [state, setState] = useState<ProofRoomState>({ status: 'loading' })
  const [bundleSource, setBundleSource] = useState<string>('served')
  const [fixtureCatalog, setFixtureCatalog] = useState<ProofRoomFixtureCatalog | null>(null)
  const [uploadError, setUploadError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    Promise.all([
      fetchProofRoomStaticBundle().then(assertProofRoomBundle),
      fetchProofRoomFixtureCatalog(),
    ])
      .then(([bundle, catalog]) => {
        if (active) {
          setFixtureCatalog(catalog)
          setState({ status: 'loaded', bundle })
        }
      })
      .catch((error: unknown) => {
        if (active) {
          setState({
            status: 'error',
            message: error instanceof Error ? error.message : 'Proof Room load failed',
          })
        }
      })

    return () => {
      active = false
    }
  }, [])

  async function handleBundleFilesSelected(event: ChangeEvent<HTMLInputElement>) {
    const files = event.currentTarget.files
    if (!files || files.length === 0) {
      return
    }

    try {
      const uploadedFiles = Array.from(files) as UploadedProofRoomFile[]
      await verifySelectedProofRoomBundleUpload(uploadedFiles)
      const bundle = await readSelectedProofRoomBundle(uploadedFiles)
      setState({ status: 'loaded', bundle })
      setBundleSource('selected')
      setFixtureCatalog(null)
      setUploadError(null)
    } catch (error: unknown) {
      setUploadError(error instanceof Error ? error.message : 'selected Proof Room bundle failed')
    }
  }

  async function handleRenderFixture(fixture: ProofRoomAvailableFixture) {
    setUploadError(null)
    try {
      const bundle = await fetchProofRoomFixtureBundle(
        fixture.id,
        fixture.kind,
        fixture.negative_cases ?? [],
      )
      setState({ status: 'loaded', bundle: assertProofRoomBundle(bundle) })
      setBundleSource(`fixture: ${fixture.id}`)
    } catch (error: unknown) {
      setUploadError(error instanceof Error ? error.message : 'fixture Proof Room load failed')
    }
  }

  const recoveryControls = (
    <>
      <section className="proof-room-upload">
        <label className="proof-room-file-button">
          Load bundle
          <input
            type="file"
            accept="application/json,.json"
            multiple
            {...({ webkitdirectory: '', directory: '' } as Record<string, string>)}
            onChange={handleBundleFilesSelected}
          />
        </label>
        <span className="proof-room-source">Source: {bundleSource}</span>
        {uploadError ? <span className="proof-room-upload-error">{uploadError}</span> : null}
      </section>
      <FixtureCatalog catalog={fixtureCatalog} onRenderFixture={handleRenderFixture} />
    </>
  )

  if (state.status === 'loading') {
    return (
      <main className="main-content proof-room-main">
        <div className="state-loading">Loading Proof Room...</div>
      </main>
    )
  }

  if (state.status === 'error') {
    return (
      <main className="main-content proof-room-main">
        <section className="operator-summary-state operator-summary-error">
          Proof Room load failed: {state.message}
        </section>
        {recoveryControls}
      </main>
    )
  }

  const { manifest, loadReport } = state.bundle
  const { verifierReport } = state.bundle
  const artifacts = primaryArtifacts(manifest.claims)
  const receiptCoverage = manifest.receipt_coverage ?? []
  const verifiedClaims = verifierReport.verified_claims ?? []

  return (
    <main className="main-content proof-room-main">
      <section className="proof-room-summary">
        <div>
          <h2>Proof Room</h2>
          <p>Verifier report view. The UI consumes verifier output and does not mint verdicts.</p>
        </div>
        <span className={`proof-room-verdict ${verdictClass(loadReport.verdict)}`}>
          Primary verdict {loadReport.verdict}
        </span>
      </section>

      {recoveryControls}

      <section className="proof-room-grid">
        <div className="proof-room-panel">
          <span className="operator-card-label">Bundle</span>
          <strong>{manifest.bundle_id}</strong>
          <span>{manifest.fixture_id}</span>
        </div>
        <div className="proof-room-panel">
          <span className="operator-card-label">Verifier Report</span>
          <strong>{loadReport.source_verifier_report_ref.path}</strong>
          <code>{loadReport.source_verifier_report_ref.sha256}</code>
        </div>
      </section>

      <RuntimeEnforcement evidence={state.bundle.runtimeEvidence} />

      <CommerceOrder evidence={state.bundle.commerceEvidence} />

      <DisclosureLineage evidence={state.bundle.disclosureEvidence} />

      <CryptoContext evidence={state.bundle.cryptoContextEvidence} />

      <SwarmAuthority evidence={state.bundle.swarmEvidence} />

      <WorkflowPreflight evidence={state.bundle.workflowPreflightEvidence} />

      <EnterpriseExport evidence={state.bundle.enterpriseEvidence} />

      <TrustMarketContext evidence={state.bundle.trustMarketEvidence} />

      <PublicSettlement
        proof={state.bundle.publicSettlementProof}
        verifierReport={state.bundle.publicSettlementVerifierReport}
      />

      <section className="proof-room-section">
        <h3>Verifier Report</h3>
        <div className="proof-room-grid">
          <div className="proof-room-panel">
            <span className="operator-card-label">Schema</span>
            <strong>{verifierReport.schema}</strong>
            {verifierReport.id ? <span>{verifierReport.id}</span> : null}
          </div>
          {verifierReport.passport_id ? (
            <div className="proof-room-panel">
              <span className="operator-card-label">Passport</span>
              <strong>{verifierReport.passport_id}</strong>
              {verifierReport.passport_path ? <span>{verifierReport.passport_path}</span> : null}
            </div>
          ) : null}
          {verifierReport.evidence_graph_path ? (
            <div className="proof-room-panel">
              <span className="operator-card-label">Evidence Graph</span>
              <strong>{verifierReport.evidence_graph_path}</strong>
            </div>
          ) : null}
          {verifierReport.verifier_policy_path ? (
            <div className="proof-room-panel">
              <span className="operator-card-label">Verifier Policy</span>
              <strong>{verifierReport.verifier_policy_path}</strong>
            </div>
          ) : null}
          {verifierReport.failure_code || verifierReport.error ? (
            <div className="proof-room-panel">
              <span className="operator-card-label">Failure</span>
              {verifierReport.failure_code ? (
                <strong>{verifierReport.failure_code}</strong>
              ) : null}
              {verifierReport.error ? <span>{verifierReport.error}</span> : null}
            </div>
          ) : null}
        </div>
        {verifiedClaims.length > 0 ? (
          <div className="proof-room-artifacts">
            {verifiedClaims.map((claim) => (
              <code key={claim}>{claim}</code>
            ))}
          </div>
        ) : null}
      </section>

      <RiskComptroller report={state.bundle.riskReport} />

      <AgentWebProjections projections={state.bundle.agentWebProjections ?? []} />

      <section className="proof-room-section">
        <h3>Rendered Claims</h3>
        <div className="proof-room-table-wrap">
          <table className="receipt-table proof-room-table">
            <thead>
              <tr>
                <th>Claim</th>
                <th>Source</th>
                <th>Checker</th>
                <th>Verdict</th>
              </tr>
            </thead>
            <tbody>
              {loadReport.rendered_claims.map((claim) => (
                <tr key={`${claim.claim_id}:${claim.source}`}>
                  <td>{claim.claim_id}</td>
                  <td>{claim.source}</td>
                  <td>{claim.checker ?? 'verifier report'}</td>
                  <td>
                    <span className={`proof-room-verdict-chip ${verdictClass(claim.verdict)}`}>
                      {formatVerdict(claim.verdict)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="proof-room-section">
        <h3>Manifest Claims</h3>
        <div className="proof-room-list">
          {manifest.claims.map((claim) => (
            <div className="proof-room-row" key={claim.claim_id}>
              <div>
                <strong>{claim.claim_id}</strong>
                <span>{claim.checker ?? 'verifier report'}</span>
              </div>
              <span className={`proof-room-verdict-chip ${verdictClass(claim.result)}`}>
                {formatVerdict(claim.result)}
              </span>
            </div>
          ))}
        </div>
      </section>

      <section className="proof-room-section">
        <h3>Primary Artifacts</h3>
        <div className="proof-room-artifacts">
          {artifacts.map((artifact) => (
            <code key={artifact}>{artifact}</code>
          ))}
        </div>
      </section>

      <section className="proof-room-section">
        <h3>Receipt Coverage</h3>
        <ReceiptCoverage rows={receiptCoverage} />
      </section>

      <section className="proof-room-section">
        <h3>Negative Cases</h3>
        <NegativeCases cases={manifest.negative_cases} />
      </section>
    </main>
  )
}
