import type { ReactNode } from 'react'
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'

import {
  fetchProofRoomFixtureBundle,
  fetchProofRoomFixtureVerifierReport,
  fetchProofRoomStaticBundle,
} from './api'
import App from './App'
import { sha256Hex } from './proofRoomArtifactEvidence'

async function renderIntoDocument(node: ReactNode): Promise<HTMLDivElement> {
  const container = document.createElement('div')
  document.body.appendChild(container)
  const root = createRoot(container)
  await act(async () => {
    root.render(node)
    await Promise.resolve()
  })
  return container
}

function bytesToHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
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

async function waitForText(container: HTMLElement, text: string): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (container.textContent?.includes(text)) {
      return
    }
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10))
    })
  }

  throw new Error(`timed out waiting for text: ${text}`)
}

async function waitForAnyText(container: HTMLElement, texts: string[]): Promise<string> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const matched = texts.find((text) => container.textContent?.includes(text))
    if (matched) {
      return matched
    }
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10))
    })
  }

  throw new Error(`timed out waiting for text: ${texts.join(', ')}`)
}

function buttonWithText(container: HTMLElement, text: string): HTMLButtonElement {
  const button = Array.from(container.querySelectorAll('button'))
    .find((candidate) => candidate.textContent === text)
  if (!(button instanceof HTMLButtonElement)) {
    throw new Error(`missing button: ${text}`)
  }
  return button
}

type MockFetchRoute = unknown | ((url: string, init?: RequestInit) => unknown | Promise<unknown>)
const mockJsonBody: unique symbol = Symbol('mockJsonBody')

interface MockJsonResponse {
  ok: boolean
  status: number
  statusText?: string
  json: () => Promise<unknown>
  [mockJsonBody]: unknown
}

interface SignedMockProofRoomManifest {
  manifest: Record<string, unknown>
  signatureUrl: string
  signatureText: string
  signerKeyId: string
}

const mockTrustedProofRoomSignerKeys = new Set<string>()

function jsonResponse(
  body: unknown,
  init: { ok?: boolean; status?: number; statusText?: string } = {},
): MockJsonResponse {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    ...(init.statusText ? { statusText: init.statusText } : {}),
    [mockJsonBody]: body,
    json: async () => body,
  }
}

function textResponse(body: string, init: { ok?: boolean; status?: number; statusText?: string } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    ...(init.statusText ? { statusText: init.statusText } : {}),
    text: async () => body,
  }
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined
}

function mockJsonResponseBody(response: unknown): unknown | undefined {
  const record = objectRecord(response)
  return record && mockJsonBody in record ? record[mockJsonBody] : undefined
}

function proofRoomSignatureUrl(manifestUrl: string, signatureRef: string): string {
  const base = manifestUrl.endsWith('/manifest.json')
    ? manifestUrl.slice(0, -'/manifest.json'.length)
    : ''
  return base ? `${base}/${signatureRef}` : `/${signatureRef}`
}

async function signMockProofRoomManifest(
  manifestUrl: string,
  body: Record<string, unknown>,
): Promise<SignedMockProofRoomManifest> {
  const signatureRef = 'bundle-signature.dsse.json'
  const manifest = {
    ...body,
    signature: {
      kind: 'detached-dsse',
      signature_ref: signatureRef,
    },
  }
  const manifestText = JSON.stringify(manifest)
  const keypair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair
  const signerKeyId = bytesToHex(await crypto.subtle.exportKey('raw', keypair.publicKey))
  const signatureBytes = await crypto.subtle.sign(
    { name: 'Ed25519' },
    keypair.privateKey,
    dssePreAuthEncoding(proofRoomBundlePayloadType, manifestText),
  )
  mockTrustedProofRoomSignerKeys.add(signerKeyId)
  return {
    manifest,
    signatureUrl: proofRoomSignatureUrl(manifestUrl, signatureRef),
    signerKeyId,
    signatureText: JSON.stringify({
      payloadType: proofRoomBundlePayloadType,
      payloadRef: {
        path: 'manifest.json',
        schema: 'chio.proof-room.bundle.v1',
        sha256: await sha256Hex(manifestText),
      },
      signatures: [{ keyid: signerKeyId, sig: bytesToHex(signatureBytes) }],
    }),
  }
}

function mockFetch(routes: Record<string, MockFetchRoute>) {
  mockTrustedProofRoomSignerKeys.clear()
  const signatures = new Map<string, Promise<SignedMockProofRoomManifest>>()
  const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (!Object.prototype.hasOwnProperty.call(routes, url)) {
      if (url === '/proof-room-trusted-bundle-signers.json') {
        return jsonResponse({
          schema: 'chio.proof-room.trusted-bundle-signers.v1',
          keys: Array.from(mockTrustedProofRoomSignerKeys),
        })
      }
      if (url === '/proof-room/upload/verify') {
        return jsonResponse({
          schema: 'chio.proof-room.upload-verification.v1',
          verdict: 'verified',
          bundle_id: 'mock-uploaded-proof-room',
        })
      }
      const signature = signatures.get(url)
      if (signature) {
        return textResponse((await signature).signatureText)
      }
      if (url === '/proof-room-fixture-catalog.json') {
        return jsonResponse(null, {
          ok: false,
          status: 404,
          statusText: 'Not Found',
        })
      }
      return Promise.reject(new Error(`unexpected fetch: ${url}`))
    }

    const route = routes[url]
    const response = await Promise.resolve(typeof route === 'function' ? route(url, init) : route)
    const body = objectRecord(mockJsonResponseBody(response))
    if (
      body
      && body.schema === 'chio.proof-room.bundle.v1'
      && !body.signature
      && objectRecord(response)?.ok !== false
    ) {
      const signature = signMockProofRoomManifest(url, body)
      signatures.set((await signature).signatureUrl, signature)
      return jsonResponse(await signature.then((signed) => signed.manifest), {
        status: Number(objectRecord(response)?.status ?? 200),
        statusText: typeof objectRecord(response)?.statusText === 'string'
          ? objectRecord(response)?.statusText as string
          : undefined,
      })
    }
    return response
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function uploadedJsonFile(contents: string, path: string): File {
  return new File([contents], path, { type: 'application/json' })
}

const proofRoomBundlePayloadType = 'application/vnd.chio.proof-room.bundle.v1+json'

async function generatedProofRoomSigner(): Promise<{
  keypair: CryptoKeyPair
  signerKeyId: string
}> {
  const keypair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair
  const signerKeyId = bytesToHex(await crypto.subtle.exportKey('raw', keypair.publicKey))
  return { keypair, signerKeyId }
}

async function signedProofRoomManifestFileWithSigner(
  manifestJson: string,
  keypair: CryptoKeyPair,
  signerKeyId: string,
  trusted = true,
): Promise<File> {
  if (trusted) {
    mockTrustedProofRoomSignerKeys.add(signerKeyId)
  }
  const signatureBytes = await crypto.subtle.sign(
    { name: 'Ed25519' },
    keypair.privateKey,
    dssePreAuthEncoding(proofRoomBundlePayloadType, manifestJson),
  )
  return uploadedJsonFile(
    JSON.stringify({
      payloadType: proofRoomBundlePayloadType,
      payloadRef: {
        path: 'manifest.json',
        schema: 'chio.proof-room.bundle.v1',
        sha256: await sha256Hex(manifestJson),
      },
      signatures: [{ keyid: signerKeyId, sig: bytesToHex(signatureBytes) }],
    }),
    'bundle-signature.dsse.json',
  )
}

async function signedProofRoomManifestFile(manifestJson: string): Promise<File> {
  const { keypair, signerKeyId } = await generatedProofRoomSigner()
  return signedProofRoomManifestFileWithSigner(manifestJson, keypair, signerKeyId)
}

function selectedVerifierRootFiles(prefix = 'roots'): [File, File, File] {
  const root = prefix ? `${prefix}/` : ''
  return [
    uploadedJsonFile('{}', `${root}transaction-passport.json`),
    uploadedJsonFile('{}', `${root}evidence-graph.json`),
    uploadedJsonFile('{}', `${root}verifier-policy.json`),
  ]
}

async function selectedVerifiedProofRoomFiles(
  bundleId = 'uploaded-proof-room',
  fixtureId = 'uploaded-fixture',
  claimId = 'claim.proof_room.upload_verified',
): Promise<File[]> {
  const verifierReportJson = JSON.stringify({
    schema: 'chio.transaction.verifier-report.v1',
    id: `${bundleId}-verifier-report`,
    verdict: 'verified',
    passport_id: `${bundleId}-passport`,
    passport_path: 'transaction-passport.json',
    evidence_graph_path: 'evidence-graph.json',
    verifier_policy_path: 'verifier-policy.json',
    verified_claims: [claimId],
  })
  const verifierReportDigest = await sha256Hex(verifierReportJson)
  const loadReportJson = JSON.stringify({
    schema: 'chio.proof-room.verifier-report.v1',
    verdict: 'verified',
    bundle_id: bundleId,
    fixture_id: fixtureId,
    source_verifier_report_ref: {
      path: 'verifier/report.json',
      sha256: verifierReportDigest,
      schema: 'chio.transaction.verifier-report.v1',
    },
    ui_verdict_source: 'verifier_report_ref',
    rendered_claims: [
      {
        claim_id: claimId,
        source: 'verifier/report.json',
        verdict: 'verified',
      },
    ],
  })
  const loadReportDigest = await sha256Hex(loadReportJson)
  const manifestJson = JSON.stringify({
    schema: 'chio.proof-room.bundle.v1',
    bundle_id: bundleId,
    fixture_id: fixtureId,
    verifier_report_ref: {
      path: 'verifier/report.json',
      sha256: verifierReportDigest,
      schema: 'chio.transaction.verifier-report.v1',
    },
    proof_room_verifier_report_ref: {
      path: 'ui/proof-room-static/load-report.json',
      sha256: loadReportDigest,
      schema: 'chio.proof-room.verifier-report.v1',
    },
    signature: {
      kind: 'detached-dsse',
      signature_ref: 'bundle-signature.dsse.json',
    },
    claims: [
      {
        claim_id: claimId,
        required_artifacts: ['verifier/report.json'],
        result: 'verified',
      },
    ],
    negative_cases: [],
  })
  const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()
  return [
    uploadedJsonFile(manifestJson, 'manifest.json'),
    await signedProofRoomManifestFile(manifestJson),
    new File([loadReportJson], 'ui/proof-room-static/load-report.json', {
      type: 'application/json',
    }),
    new File([verifierReportJson], 'verifier/report.json', {
      type: 'application/json',
    }),
    transactionPassport,
    evidenceGraph,
    verifierPolicy,
  ]
}

function servedProofRoomRoutes(
  bundleId = 'proof-room-single-call-authority',
  fixtureId = 'single-call-authority',
  verifierReportDigest = 'served-report-digest',
  verifierReport: Record<string, unknown> = {},
): Record<string, MockFetchRoute> {
  return {
    '/manifest.json': jsonResponse({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: bundleId,
      fixture_id: fixtureId,
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      claims: [],
      negative_cases: [],
    }),
    '/ui/proof-room-static/load-report.json': jsonResponse({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: bundleId,
      fixture_id: fixtureId,
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [],
    }),
    '/verifier/report.json': jsonResponse({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'served-verifier-report',
      verdict: 'verified',
      verified_claims: [],
      ...verifierReport,
    }),
  }
}

function servedProofRoomRoutesWithVerifierRoots(): Record<string, MockFetchRoute> {
  return servedProofRoomRoutes('served-proof-room', 'single-call-authority', 'served-report-digest', {
    passport_id: 'served-passport',
    passport_path: 'transaction-passport.json',
    evidence_graph_path: 'evidence-graph.json',
    verifier_policy_path: 'verifier-policy.json',
  })
}

describe('App operator paths', () => {
  it('keeps Proof Room mode when token cleanup strips the URL secret', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room&token=proof-room-token')
    const fetchMock = mockFetch(servedProofRoomRoutes('served-proof-room', 'single-call-authority'))

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    expect(container.textContent).toContain('Chio Proof Room')
    expect(container.textContent).not.toContain('Chio Receipt Dashboard')
    expect(window.location.search).toBe('?view=proof-room')
    expect(fetchMock).not.toHaveBeenCalledWith(
      expect.stringMatching(/^\/v1\/receipts\/query/),
      expect.anything(),
    )
  })

  it('renders static Proof Room data without bearer token prompts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
            schema: 'chio.proof-room.bundle.v1',
            bundle_id: 'proof-room-single-call-authority',
            fixture_id: 'single-call-authority',
            verifier_report_ref: {
              path: 'verifier/report.json',
              sha256: '92368d844cd82f5504234516c0072755be99080f073258ad4ce96a5c5fe16877',
              schema: 'chio.transaction.verifier-report.v1',
            },
            claims: [
              {
                claim_id: 'claim.transaction.passport_root_verified',
                required_artifacts: [
                  'roots/transaction-passport.json',
                  'verifier/report.json',
                ],
                result: 'verified',
              },
              {
                claim_id: 'claim.proof_room.verifier_report_bound',
                required_artifacts: [
                  'verifier/report.json',
                  'ui/proof-room-static/load-report.json',
                ],
                result: 'verified',
              },
              {
                claim_id: 'claim.proof_room.allow_and_deny_visible',
                required_artifacts: [
                  'artifacts/receipts/allow-receipt.json',
                  'artifacts/receipts/denial-receipt.json',
                ],
                result: 'verified',
              },
              {
                claim_id: 'claim.proof_room.receipt_coverage_matrix_bound',
                required_artifacts: [
                  'artifacts/receipts/allow-receipt.json',
                  'artifacts/receipts/denial-receipt.json',
                ],
                result: 'verified',
              },
            ],
            negative_cases: [
              {
                id: 'policy-hash-mismatch',
                path: 'negatives/policy-hash-mismatch/transaction-passport.json',
                expected_failure_code: 'verifier policy digest mismatch',
                observed_failure_code: 'proof verify: verifier policy digest mismatch',
              },
            ],
            receipt_coverage: [
              {
                category: 'runtime_terminal_allow',
                status: 'covered',
                artifact_path: 'artifacts/receipts/allow-receipt.json',
                terminal_status: 'allowed_executed',
              },
              {
                category: 'runtime_terminal_denial',
                status: 'covered',
                artifact_path: 'artifacts/receipts/denial-receipt.json',
                terminal_status: 'denied_guard_request',
              },
              {
                category: 'runtime_terminal_failure',
                status: 'excluded',
                exclusion_reason:
                  'Single-call authority fixture covers allow and guard denial terminal receipts only.',
              },
            ],
          }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
            schema: 'chio.proof-room.verifier-report.v1',
            verdict: 'verified',
            bundle_id: 'proof-room-single-call-authority',
            fixture_id: 'single-call-authority',
            source_verifier_report_ref: {
              path: 'verifier/report.json',
              sha256: '92368d844cd82f5504234516c0072755be99080f073258ad4ce96a5c5fe16877',
              schema: 'chio.transaction.verifier-report.v1',
            },
            ui_verdict_source: 'verifier_report_ref',
            rendered_claims: [
              {
                claim_id: 'claim.transaction.passport_root_verified',
                source: 'verifier/report.json',
                verdict: 'verified',
              },
              {
                claim_id: 'claim.proof_room.verifier_report_bound',
                source: 'verifier/report.json',
                verdict: 'verified',
              },
              {
                claim_id: 'claim.proof_room.allow_and_deny_visible',
                source: 'artifacts/receipts/allow-receipt.json',
                verdict: 'verified',
              },
              {
                claim_id: 'claim.proof_room.receipt_coverage_matrix_bound',
                source: 'artifacts/receipts/denial-receipt.json',
                verdict: 'verified',
              },
            ],
          }),
      '/verifier/report.json': jsonResponse({
            schema: 'chio.transaction.verifier-report.v1',
            id: 'verifier-report-passport-minimal-valid',
            verdict: 'verified',
            passport_id: 'passport-minimal-valid',
            passport_path: 'transaction-passport.json',
            evidence_graph_path: 'evidence-graph.json',
            verifier_policy_path: 'verifier-policy.json',
            verified_claims: ['claim.transaction.passport_root_verified'],
          }),
      '/proof-room-fixture-catalog.json': jsonResponse({
            schema: 'chio.proof-room.fixture-catalog.v1',
            fixtures: [
              {
                fixture_id: 'single-call-authority',
                bundle_id: 'proof-room-single-call-authority',
                verdict: 'verified',
                manifest_path: 'manifest.json',
                load_report_path: 'ui/proof-room-static/load-report.json',
                negative_cases: [
                  {
                    id: 'policy-hash-mismatch',
                    path: 'negatives/policy-hash-mismatch/transaction-passport.json',
                    expected_failure_code: 'verifier policy digest mismatch',
                    observed_failure_code: 'proof verify: verifier policy digest mismatch',
                  },
                ],
              },
            ],
            available_fixtures: [
              {
                id: 'single-call-authority',
                kind: 'proof-room',
                path: 'fixtures/proof-room/first-run/single-call-authority',
                description: 'Stage 0 first-run Proof Room bundle with allow and denial receipts',
                verifier_report: {
                  path: '/proof-room-fixtures/single-call-authority/verifier-report.json',
                  status: 200,
                  verdict: 'verified',
                },
              },
              {
                id: 'minimal-passport-valid',
                kind: 'transaction-passport',
                path: 'fixtures/proof-room/minimal-passport/valid',
                description: 'Minimal valid Transaction Passport verifier fixture',
                verifier_report: {
                  path: '/proof-room-fixtures/minimal-passport-valid/verifier-report.json',
                  status: 200,
                  verdict: 'verified',
                },
              },
              {
                id: 'commerce-offline-psp',
                kind: 'transaction-passport',
                path: 'fixtures/proof-room/commerce-payments/offline-psp-valid',
                description: 'Commerce payment fixture with order replay evidence',
                verifier_report: {
                  path: '/proof-room-fixtures/commerce-offline-psp/verifier-report.json',
                  status: 200,
                  verdict: 'verified',
                },
              },
              {
                id: 'agent-web-external-digest-mismatch',
                kind: 'negative-transaction-passport',
                path: 'fixtures/proof-room/agent-web/external-digest-mismatch',
                description: 'Agent Web fixture rejected when the external subject digest changes',
                verifier_report: {
                  path: '/proof-room-fixtures/agent-web-external-digest-mismatch/verifier-report.json',
                  status: 422,
                  verdict: 'failed',
                  failure_code: 'proof-room.fixture.verify-failed',
                  error:
                    'proof-room.fixture.verify-failed: agent-web-external-digest-mismatch: external subject digest mismatch',
                },
              },
            ],
          }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'passport-minimal-valid')

    const bundleInput = container.querySelector('input[type="file"]')
    expect(bundleInput?.hasAttribute('webkitdirectory')).toBe(true)
    expect(bundleInput?.hasAttribute('directory')).toBe(true)
    expect(container.textContent).toContain('proof-room-single-call-authority')
    expect(fetchMock).toHaveBeenCalledWith('/verifier/report.json')
    expect(container.textContent).toContain('chio.transaction.verifier-report.v1')
    expect(container.textContent).toContain('transaction-passport.json')
    expect(container.textContent).toContain('evidence-graph.json')
    expect(container.textContent).toContain('verifier-policy.json')
    expect(container.textContent).toContain('claim.transaction.passport_root_verified')
    expect(container.textContent).toContain('claim.proof_room.allow_and_deny_visible')
    expect(container.textContent).toContain('claim.proof_room.receipt_coverage_matrix_bound')
    expect(container.textContent).toContain('policy-hash-mismatch')
    expect(container.textContent).toContain('verifier policy digest mismatch')
    expect(container.textContent).toContain('proof verify: verifier policy digest mismatch')
    expect(container.textContent).toContain('Fixture Catalog')
    expect(container.textContent).toContain('minimal-passport-valid')
    expect(container.textContent).toContain('Commerce payment fixture with order replay evidence')
    expect(container.textContent).toContain('agent-web-external-digest-mismatch')
    expect(container.textContent).toContain('proof-room.fixture.verify-failed')
    expect(container.textContent).toContain('external subject digest mismatch')
    expect(
      container.querySelector(
        'a[href="/proof-room-fixtures/minimal-passport-valid/transaction-passport.json"]',
      )?.textContent,
    ).toContain('Open passport')
    expect(
      container.querySelector(
        'a[href="/proof-room-fixtures/single-call-authority/proof-room-bundle/manifest.json"]',
      )?.textContent,
    ).toContain('Open bundle')
    expect(
      container.querySelector(
        'a[href="/proof-room-fixtures/single-call-authority/transaction-passport.json"]',
      ),
    ).toBeNull()
    expect(
      container.querySelector(
        'a[href="/proof-room-fixtures/minimal-passport-valid/verifier-report.json"]',
      )?.textContent,
    ).toContain('Open report')
    expect(container.textContent).toContain('manifest.json')
    expect(container.textContent).toContain('ui/proof-room-static/load-report.json')
    expect(container.textContent).toContain('runtime_terminal_allow')
    expect(container.textContent).toContain('allowed_executed')
    expect(container.textContent).toContain('runtime_terminal_failure')
    expect(container.textContent).toContain(
      'Single-call authority fixture covers allow and guard denial terminal receipts only.',
    )
    expect(container.textContent).not.toContain('Bearer token required')
  })

  it('renders first-run Proof Room fixture bundles from the catalog', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const fetchMock = mockFetch({
      ...servedProofRoomRoutes('served-proof-room', 'served'),
      '/proof-room-fixture-catalog.json': jsonResponse({
            schema: 'chio.proof-room.fixture-catalog.v1',
            fixtures: [],
            available_fixtures: [
              {
                id: 'single-call-authority',
                kind: 'proof-room',
                path: 'fixtures/proof-room/first-run/single-call-authority',
                description: 'Stage 0 first-run Proof Room bundle',
                verifier_report: {
                  path: '/proof-room-fixtures/single-call-authority/proof-room-bundle/verifier/report.json',
                  status: 200,
                  verdict: 'verified',
                },
              },
            ],
          }),
      '/proof-room-fixtures/single-call-authority/proof-room-bundle/manifest.json': jsonResponse({
            schema: 'chio.proof-room.bundle.v1',
            bundle_id: 'proof-room-single-call-authority',
            fixture_id: 'single-call-authority',
            verifier_report_ref: {
              path: 'verifier/report.json',
              sha256: 'fixture-report-digest',
              schema: 'chio.transaction.verifier-report.v1',
            },
            proof_room_verifier_report_ref: {
              path: 'ui/proof-room-static/load-report.json',
              sha256: 'fixture-load-report-digest',
              schema: 'chio.proof-room.verifier-report.v1',
            },
            claims: [
              {
                claim_id: 'claim.proof_room.authority_evidence_bound',
                required_artifacts: ['artifacts/authority/capability-proof.json'],
                result: 'verified',
              },
            ],
            negative_cases: [],
            receipt_coverage: [
              {
                category: 'runtime_terminal_denial',
                status: 'covered',
                artifact_path: 'artifacts/receipts/denial-receipt.json',
                terminal_status: 'denied_guard_request',
              },
            ],
          }),
      '/proof-room-fixtures/single-call-authority/proof-room-bundle/ui/proof-room-static/load-report.json': jsonResponse({
            schema: 'chio.proof-room.verifier-report.v1',
            verdict: 'verified',
            bundle_id: 'proof-room-single-call-authority',
            fixture_id: 'single-call-authority',
            source_verifier_report_ref: {
              path: 'verifier/report.json',
              sha256: 'fixture-report-digest',
              schema: 'chio.transaction.verifier-report.v1',
            },
            ui_verdict_source: 'verifier_report_ref',
            rendered_claims: [
              {
                claim_id: 'claim.proof_room.authority_evidence_bound',
                source: 'artifacts/authority/capability-proof.json',
                verdict: 'verified',
              },
            ],
          }),
      '/proof-room-fixtures/single-call-authority/proof-room-bundle/verifier/report.json': jsonResponse({
            schema: 'chio.transaction.verifier-report.v1',
            id: 'fixture-verifier-report',
            verdict: 'verified',
            verified_claims: ['claim.proof_room.authority_evidence_bound'],
          }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Stage 0 first-run Proof Room bundle')

    await act(async () => {
      buttonWithText(container, 'Render fixture').click()
      await Promise.resolve()
    })

    await waitForText(container, 'fixture: single-call-authority')
    expect(fetchMock).toHaveBeenCalledWith(
      '/proof-room-fixtures/single-call-authority/proof-room-bundle/manifest.json',
    )
    expect(fetchMock).toHaveBeenCalledWith(
      '/proof-room-fixtures/single-call-authority/proof-room-bundle/ui/proof-room-static/load-report.json',
    )
    expect(container.textContent).toContain('proof-room-single-call-authority')
    expect(container.textContent).toContain('claim.proof_room.authority_evidence_bound')
    expect(container.textContent).toContain('artifacts/authority/capability-proof.json')
    expect(container.textContent).toContain('runtime_terminal_denial')
    expect(container.textContent).not.toContain('transaction-passport.json')
  })

  it('renders selected failed fixture verifier reports from the Proof Room catalog', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const fetchMock = mockFetch({
      ...servedProofRoomRoutes(),
      '/proof-room-fixture-catalog.json': jsonResponse({
            schema: 'chio.proof-room.fixture-catalog.v1',
            fixtures: [],
            available_fixtures: [
              {
                id: 'agent-web-external-digest-mismatch',
                kind: 'negative-transaction-passport',
                path: 'fixtures/proof-room/agent-web/external-digest-mismatch',
                description: 'Agent Web fixture rejected when the external subject digest changes',
                verifier_report: {
                  path: '/proof-room-fixtures/agent-web-external-digest-mismatch/verifier-report.json',
                  status: 422,
                  verdict: 'failed',
                  failure_code: 'proof-room.fixture.verify-failed',
                  error:
                    'proof-room.fixture.verify-failed: agent-web-external-digest-mismatch: external subject digest mismatch',
                },
              },
            ],
          }),
      '/proof-room-fixtures/agent-web-external-digest-mismatch/verifier-report.json': jsonResponse(
        {
            schema: 'chio.transaction.verifier-report.v1',
            id: 'verifier-report-agent-web-external-digest-mismatch',
            fixture_id: 'agent-web-external-digest-mismatch',
            verdict: 'failed',
            failure_code: 'proof-room.fixture.verify-failed',
            error:
              'proof-room.fixture.verify-failed: agent-web-external-digest-mismatch: external subject digest mismatch',
            verified_claims: [],
          },
        {
          ok: false,
          status: 422,
          statusText: 'Unprocessable Entity',
        },
      ),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'agent-web-external-digest-mismatch')

    await act(async () => {
      buttonWithText(container, 'Inspect report').click()
      await Promise.resolve()
    })

    await waitForText(container, 'chio.transaction.verifier-report.v1')
    expect(fetchMock).toHaveBeenCalledWith(
      '/proof-room-fixtures/agent-web-external-digest-mismatch/verifier-report.json',
    )
    expect(container.textContent).toContain('Selected Fixture Report')
    expect(container.textContent).toContain('chio.transaction.verifier-report.v1')
    expect(container.textContent).toContain('proof-room.fixture.verify-failed')
    expect(container.textContent).toContain('external subject digest mismatch')
    expect(container.textContent).not.toContain('Static asset request failed')
  })

  it('renders selected domain fixture verifier reports from the Proof Room catalog', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      ...servedProofRoomRoutes(),
      '/proof-room-fixture-catalog.json': jsonResponse({
        schema: 'chio.proof-room.fixture-catalog.v1',
        fixtures: [],
        available_fixtures: [
          {
            id: 'commerce-offline-psp',
            kind: 'transaction-passport',
            path: 'fixtures/proof-room/commerce-payments/offline-psp-valid',
            description: 'Commerce payment fixture with order replay evidence',
            verifier_report: {
              path: '/proof-room-fixtures/commerce-offline-psp/verifier-report.json',
              status: 200,
              verdict: 'verified',
            },
          },
          {
            id: 'runtime-side-effecting-call',
            kind: 'transaction-passport',
            path: 'fixtures/proof-room/runtime-security/valid-side-effecting-call',
            description: 'Runtime security fixture with online enforcement evidence',
            verifier_report: {
              path: '/proof-room-fixtures/runtime-side-effecting-call/verifier-report.json',
              status: 200,
              verdict: 'verified',
            },
          },
          {
            id: 'crypto-context-valid-bbs',
            kind: 'disclosure-crypto-context',
            path: 'fixtures/proof-room/crypto-context/valid-bbs-context',
            description: 'Crypto context fixture with BBS verification context',
            verifier_report: {
              path: '/proof-room-fixtures/crypto-context-valid-bbs/verifier-report.json',
              status: 200,
              verdict: 'verified',
            },
          },
          {
            id: 'agent-web-interop',
            kind: 'transaction-passport',
            path: 'fixtures/proof-room/agent-web/valid-webhook-cloudevents',
            description: 'Agent Web interop fixture with external protocol projections',
            verifier_report: {
              path: '/proof-room-fixtures/agent-web-interop/verifier-report.json',
              status: 200,
              verdict: 'verified',
            },
          },
          {
            id: 'recursive-runtime-swarm',
            kind: 'transaction-passport',
            path: 'fixtures/proof-room/swarm-authority/valid-recursive-delegation',
            description: 'Recursive swarm authority fixture with continuations and joins',
            verifier_report: {
              path: '/proof-room-fixtures/recursive-runtime-swarm/verifier-report.json',
              status: 200,
              verdict: 'verified',
            },
          },
          {
            id: 'workflow-preflight-valid',
            kind: 'workflow-preflight',
            path: 'fixtures/proof-room/workflow-preflight/valid-child-scope',
            description: 'Workflow preflight fixture proving bounded child scope',
            verifier_report: {
              path: '/proof-room-fixtures/workflow-preflight-valid/verifier-report.json',
              status: 200,
              verdict: 'verified',
            },
          },
        ],
      }),
      '/proof-room-fixtures/commerce-offline-psp/verifier-report.json': jsonResponse({
        schema: 'chio.commerce.order-passport.v1',
        id: 'commerce-order-passport-order-commerce-001',
        verdict: 'verified',
        order_id: 'order-commerce-001',
        current_state: 'completed',
        verified_claims: [
          'claim.commerce.order_replay_consistent',
          'claim.commerce.payment_lifecycle_bound',
        ],
      }),
      '/proof-room-fixtures/runtime-side-effecting-call/verifier-report.json': jsonResponse({
        schema: 'chio.transaction.runtime-security-report.v1',
        id: 'runtime-security-report-runtime-passport-valid',
        verdict: 'verified',
        passport_id: 'runtime-passport-valid',
        verified_claims: [
          'claim.runtime.execution_lease_valid',
          'claim.runtime.tool_server_ack_bound',
        ],
      }),
      '/proof-room-fixtures/crypto-context-valid-bbs/verifier-report.json': jsonResponse({
        schema: 'chio.disclosure.crypto-context-report.v1',
        id: 'disclosure-crypto-context-report-crypto-context-buyer-auditor',
        verdict: 'verified',
        context_id: 'crypto-context-buyer-auditor',
        verified_claims: [
          'claim.disclosure.crypto_context_bound',
          'claim.disclosure.profile_context_policy_enforced',
        ],
      }),
      '/proof-room-fixtures/agent-web-interop/verifier-report.json': jsonResponse({
        schema: 'chio.agent-web.interop-verifier-report.v1',
        id: 'agent-web-interop-report-passport-agent-web-valid',
        verdict: 'verified',
        passport_id: 'passport-agent-web-valid',
        verified_claims: [
          'claim.agent_web.external_subject_digest_bound',
          'claim.agent_web.unsupported_claims_limited',
        ],
      }),
      '/proof-room-fixtures/recursive-runtime-swarm/verifier-report.json': jsonResponse({
        schema: 'chio.swarm.authority-verifier-report.v1',
        id: 'swarm-authority-verifier-report-swarm-graph-proof-valid',
        verdict: 'verified',
        graphId: 'swarm-graph-proof-valid',
        verifiedClaims: [
          'claim.swarm.task_graph_bound',
          'claim.swarm.continuation_fresh',
        ],
      }),
      '/proof-room-fixtures/workflow-preflight-valid/verifier-report.json': jsonResponse({
        schema: 'chio.workflow.preflight-report.v1',
        id: 'workflow-preflight-report-workflow-preflight-valid',
        verdict: 'accepted',
        evidence_class: 'planning',
        verified_claims: ['claim.workflow.preflight_child_scope_bounded'],
        rejected_checks: [],
        live_authority_claims: [],
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'commerce-offline-psp')

    const commerceRow = Array.from(container.querySelectorAll('.proof-room-row')).find((row) =>
      row.textContent?.includes('commerce-offline-psp'),
    )
    if (!(commerceRow instanceof HTMLElement)) {
      throw new Error('missing commerce fixture row')
    }
    await act(async () => {
      buttonWithText(commerceRow, 'Inspect report').click()
      await Promise.resolve()
    })
    await waitForText(container, 'chio.commerce.order-passport.v1')
    expect(container.textContent).toContain('claim.commerce.order_replay_consistent')

    const runtimeRow = Array.from(container.querySelectorAll('.proof-room-row')).find((row) =>
      row.textContent?.includes('runtime-side-effecting-call'),
    )
    if (!(runtimeRow instanceof HTMLElement)) {
      throw new Error('missing runtime fixture row')
    }
    await act(async () => {
      buttonWithText(runtimeRow, 'Inspect report').click()
      await Promise.resolve()
    })
    await waitForText(container, 'chio.transaction.runtime-security-report.v1')
    expect(container.textContent).toContain('claim.runtime.execution_lease_valid')
    expect(container.textContent).not.toContain('fixture verifier report has unsupported schema')

    const cryptoContextRow = Array.from(container.querySelectorAll('.proof-room-row')).find((row) =>
      row.textContent?.includes('crypto-context-valid-bbs'),
    )
    if (!(cryptoContextRow instanceof HTMLElement)) {
      throw new Error('missing crypto context fixture row')
    }
    await act(async () => {
      buttonWithText(cryptoContextRow, 'Inspect report').click()
      await Promise.resolve()
    })
    await waitForText(container, 'chio.disclosure.crypto-context-report.v1')
    expect(container.textContent).toContain('claim.disclosure.crypto_context_bound')
    expect(container.textContent).not.toContain('fixture verifier report has unsupported schema')

    const agentWebRow = Array.from(container.querySelectorAll('.proof-room-row')).find((row) =>
      row.textContent?.includes('agent-web-interop'),
    )
    if (!(agentWebRow instanceof HTMLElement)) {
      throw new Error('missing Agent Web fixture row')
    }
    await act(async () => {
      buttonWithText(agentWebRow, 'Inspect report').click()
      await Promise.resolve()
    })
    await waitForText(container, 'chio.agent-web.interop-verifier-report.v1')
    expect(container.textContent).toContain('claim.agent_web.external_subject_digest_bound')
    expect(container.textContent).not.toContain('fixture verifier report has unsupported schema')

    const swarmRow = Array.from(container.querySelectorAll('.proof-room-row')).find((row) =>
      row.textContent?.includes('recursive-runtime-swarm'),
    )
    if (!(swarmRow instanceof HTMLElement)) {
      throw new Error('missing swarm fixture row')
    }
    await act(async () => {
      buttonWithText(swarmRow, 'Inspect report').click()
      await Promise.resolve()
    })
    await waitForText(container, 'chio.swarm.authority-verifier-report.v1')
    expect(container.textContent).toContain('claim.swarm.continuation_fresh')

    const workflowRow = Array.from(container.querySelectorAll('.proof-room-row')).find((row) =>
      row.textContent?.includes('workflow-preflight-valid'),
    )
    if (!(workflowRow instanceof HTMLElement)) {
      throw new Error('missing workflow fixture row')
    }
    expect(
      workflowRow.querySelector(
        'a[href="/proof-room-fixtures/workflow-preflight-valid/preflight-plan.json"]',
      )?.textContent,
    ).toContain('Open plan')
    expect(
      workflowRow.querySelector(
        'a[href="/proof-room-fixtures/workflow-preflight-valid/transaction-passport.json"]',
      ),
    ).toBeNull()
    await act(async () => {
      buttonWithText(workflowRow, 'Inspect report').click()
      await Promise.resolve()
    })
    await waitForText(container, 'chio.workflow.preflight-report.v1')
    expect(container.textContent).toContain('planning')
    expect(container.textContent).toContain('claim.workflow.preflight_child_scope_bounded')
  })

  it('renders selected catalog transaction fixture in the main Proof Room evidence view', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const fetchMock = mockFetch({
      ...servedProofRoomRoutes(),
      '/proof-room-fixture-catalog.json': jsonResponse({
        schema: 'chio.proof-room.fixture-catalog.v1',
        fixtures: [],
        available_fixtures: [
          {
            id: 'commerce-offline-psp',
            kind: 'transaction-passport',
            path: 'fixtures/proof-room/commerce-payments/offline-psp-valid',
            description: 'Commerce payment fixture with order replay evidence',
            verifier_report: {
              path: '/proof-room-fixtures/commerce-offline-psp/verifier-report.json',
              status: 200,
              verdict: 'verified',
            },
            negative_cases: [
              {
                id: 'commerce-payment-wrong-merchant',
                path: '/proof-room-fixtures/commerce-payment-wrong-merchant/transaction-passport.json',
                expected_failure_code: 'payment merchant mismatch',
                observed_failure_code: 'commerce payment failed: payment merchant mismatch',
              },
            ],
          },
        ],
      }),
      '/proof-room-fixtures/commerce-offline-psp/transaction-passport.json': jsonResponse({
        schema: 'chio.transaction-passport.v1',
        id: 'passport-commerce-001',
        evidence_graph_path: 'evidence-graph.json',
        evidence_graph_sha256: 'commerce-evidence-graph-digest',
        verifier_policy_path: 'verifier-policy.json',
        verifier_policy_sha256: 'commerce-policy-digest',
      }),
      '/proof-room-fixtures/commerce-offline-psp/evidence-graph.json': jsonResponse({
        schema: 'chio.transaction.evidence-graph.v1',
        nodes: [
          {
            id: 'commerce-order-context',
            role: 'commerce-order-context',
            schema: 'chio.commerce.order-context.v1',
            path: 'order-context.json',
            sha256: 'order-context-digest',
          },
          {
            id: 'commerce-payment-lifecycle',
            role: 'commerce-payment-lifecycle',
            schema: 'chio.commerce.payment-lifecycle.v1',
            path: 'payment-lifecycle.json',
            sha256: 'payment-lifecycle-digest',
          },
          {
            id: 'commerce-event-log',
            role: 'commerce-event-log',
            schema: 'chio.commerce.event-log.v1',
            path: 'event-log.json',
            sha256: 'event-log-digest',
          },
        ],
      }),
      '/proof-room-fixtures/commerce-offline-psp/verifier-policy.json': jsonResponse({
        schema: 'chio.verifier-policy.v1',
        required_claims: [
          'claim.commerce.order_replay_consistent',
          'claim.commerce.payment_lifecycle_bound',
        ],
      }),
      '/proof-room-fixtures/commerce-offline-psp/verifier-report.json': jsonResponse({
        schema: 'chio.commerce.order-passport.v1',
        id: 'commerce-order-passport-order-commerce-001',
        verdict: 'verified',
        order_id: 'order-commerce-001',
        current_state: 'completed',
        verified_claims: [
          'claim.commerce.order_replay_consistent',
          'claim.commerce.payment_lifecycle_bound',
        ],
      }),
      '/proof-room-fixtures/commerce-offline-psp/order-context.json': jsonResponse({
        schema: 'chio.commerce.order-context.v1',
        id: 'commerce-order-context',
        order_id: 'order-commerce-001',
        buyer_subject: 'did:chio:buyer',
        merchant_subject: 'did:chio:merchant',
        quote_amount_minor: 1250,
        quote_currency: 'USD',
        current_state: 'completed',
      }),
      '/proof-room-fixtures/commerce-offline-psp/payment-lifecycle.json': jsonResponse({
        schema: 'chio.commerce.payment-lifecycle.v1',
        id: 'payment-lifecycle-commerce-001',
        order_id: 'order-commerce-001',
        psp: 'offline-psp',
        payment_intent_id: 'pi_offline_001',
        amount_minor: 1250,
        currency: 'USD',
        payment_status: 'captured',
      }),
      '/proof-room-fixtures/commerce-offline-psp/event-log.json': jsonResponse({
        schema: 'chio.commerce.event-log.v1',
        id: 'commerce-event-log-001',
        order_id: 'order-commerce-001',
        events: [
          {
            event_id: 'commerce-event-authorized',
            transition: 'authorize',
            next_state: 'authorized',
          },
        ],
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'commerce-offline-psp')

    const commerceRow = Array.from(container.querySelectorAll('.proof-room-row')).find((row) =>
      row.textContent?.includes('commerce-offline-psp'),
    )
    if (!(commerceRow instanceof HTMLElement)) {
      throw new Error('missing commerce fixture row')
    }
    await act(async () => {
      buttonWithText(commerceRow, 'Render fixture').click()
      await Promise.resolve()
    })

    await waitForText(container, 'Source: fixture: commerce-offline-psp')
    expect(container.textContent).toContain('proof-room-commerce-offline-psp')
    expect(container.textContent).toContain('Commerce Order')
    expect(container.textContent).toContain('order-commerce-001')
    expect(container.textContent).toContain('offline-psp')
    expect(container.textContent).toContain('claim.commerce.payment_lifecycle_bound')
    expect(container.textContent).toContain('commerce-payment-wrong-merchant')
    expect(container.textContent).toContain('payment merchant mismatch')
    expect(fetchMock).toHaveBeenCalledWith(
      '/proof-room-fixtures/commerce-offline-psp/order-context.json',
    )
  })

  it('rejects fixture rendering when the verifier report omits a verifier-policy claim', async () => {
    const evidenceGraphJson = JSON.stringify({
      schema: 'chio.transaction.evidence-graph.v1',
      nodes: [],
    })
    const verifierPolicyJson = JSON.stringify({
      schema: 'chio.transaction.verifier-policy.v1',
      required_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'verifier-report-claim-drift',
      verdict: 'verified',
      passport_id: 'passport-claim-drift',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: [],
    })
    const passportJson = JSON.stringify({
      schema: 'chio.transaction-passport.v1',
      id: 'passport-claim-drift',
      evidence_graph_path: 'evidence-graph.json',
      evidence_graph_sha256: await sha256Hex(evidenceGraphJson),
      verifier_policy_path: 'verifier-policy.json',
      verifier_policy_sha256: await sha256Hex(verifierPolicyJson),
    })
    mockFetch({
      '/proof-room-fixtures/claim-drift/transaction-passport.json': textResponse(passportJson),
      '/proof-room-fixtures/claim-drift/evidence-graph.json': textResponse(evidenceGraphJson),
      '/proof-room-fixtures/claim-drift/verifier-policy.json': textResponse(verifierPolicyJson),
      '/proof-room-fixtures/claim-drift/verifier-report.json': textResponse(verifierReportJson),
    })

    await expect(fetchProofRoomFixtureBundle('claim-drift')).rejects.toThrow(
      'fixture verifier report does not verify required claim: claim.transaction.passport_root_verified',
    )
  })

  it('renders rejected workflow preflight checks from the Proof Room catalog', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      ...servedProofRoomRoutes(),
      '/proof-room-fixture-catalog.json': jsonResponse({
        schema: 'chio.proof-room.fixture-catalog.v1',
        fixtures: [],
        available_fixtures: [
          {
            id: 'workflow-preflight-broader-child-scope',
            kind: 'workflow-preflight',
            path: 'fixtures/proof-room/workflow-preflight/broader-child-scope',
            description: 'Workflow preflight fixture rejecting broader child scope',
            verifier_report: {
              path: '/proof-room-fixtures/workflow-preflight-broader-child-scope/verifier-report.json',
              status: 200,
              verdict: 'rejected',
            },
          },
        ],
      }),
      '/proof-room-fixtures/workflow-preflight-broader-child-scope/verifier-report.json': jsonResponse({
        schema: 'chio.workflow.preflight-report.v1',
        id: 'workflow-preflight-report-workflow-preflight-broader-child-scope',
        verdict: 'rejected',
        evidence_class: 'planning',
        verified_claims: [],
        rejected_checks: [
          {
            code: 'workflow_preflight_child_scope_not_bounded',
            message: 'child scope grants broader network access than parent capability',
            task_id: 'child-broader-network',
          },
        ],
        live_authority_claims: [],
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'workflow-preflight-broader-child-scope')

    await act(async () => {
      buttonWithText(container, 'Inspect report').click()
      await Promise.resolve()
    })

    await waitForText(container, 'chio.workflow.preflight-report.v1')
    expect(container.textContent).toContain('Rejected')
    expect(container.textContent).toContain('planning')
    expect(container.textContent).toContain('workflow_preflight_child_scope_not_bounded')
    expect(container.textContent).toContain(
      'child scope grants broader network access than parent capability',
    )
    expect(container.textContent).toContain('child-broader-network')
  })

  it('renders minimal transaction Proof Room data backed by the transaction verifier report', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-minimal-passport-valid',
        fixture_id: 'minimal-passport-valid',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'minimal-passport-verifier-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        claims: [
          {
            claim_id: 'claim.transaction.passport_root_verified',
            required_artifacts: ['verifier/report.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-minimal-passport-valid',
        fixture_id: 'minimal-passport-valid',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'minimal-passport-verifier-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.transaction.passport_root_verified',
            source: 'verifier/report.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.transaction.verifier-report.v1',
        id: 'verifier-report-passport-minimal-valid',
        verdict: 'verified',
        passport_id: 'passport-minimal-valid',
        passport_path: 'transaction-passport.json',
        evidence_graph_path: 'evidence-graph.json',
        verifier_policy_path: 'verifier-policy.json',
      }),
      '/proof-room-fixture-catalog.json': jsonResponse(null, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'passport-minimal-valid')

    expect(container.textContent).toContain('proof-room-minimal-passport-valid')
    expect(fetchMock).toHaveBeenCalledWith('/verifier/report.json')
    expect(container.textContent).toContain('claim.transaction.passport_root_verified')
    expect(container.textContent).toContain('transaction-passport.json')
    expect(container.textContent).not.toContain('Proof Room load failed')
  })

  it('rejects a served Proof Room fixture catalog with an unsupported schema', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      ...servedProofRoomRoutes(),
      '/proof-room-fixture-catalog.json': jsonResponse({
        schema: 'chio.proof-room.fixture-catalog.v0',
        fixtures: [],
        available_fixtures: [],
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Proof Room load failed')

    expect(container.textContent).toContain('fixture catalog has unsupported schema')
  })

  it('renders manifest-bound runtime enforcement evidence from Proof Room artifacts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const executionLeaseJson = JSON.stringify({
      schema: 'chio.runtime.execution-lease.v1',
      lease_id: 'lease-runtime-valid',
      tool_server_id: 'tool-server-payments',
      tool_instance_id: 'tool-instance-001',
      tool_manifest_digest: '1111111111111111111111111111111111111111111111111111111111111111',
      sandbox_attestation_ref: 'sandbox-runtime-valid',
      request_digest: '2222222222222222222222222222222222222222222222222222222222222222',
      revocation_freshness_ref: 'revocation-runtime-valid',
      policy_digest: '3ef61f665f58362585af0237105bac37a93554952f010664f31468c3ca94f7b6',
      nonce: 'nonce-runtime-valid',
      side_effect_class: 'network-write',
      issued_at: '2026-06-10T00:00:00Z',
      expires_at: '2026-06-10T00:05:00Z',
    })
    const revocationFreshnessJson = JSON.stringify({
      schema: 'chio.runtime.revocation-freshness-proof.v1',
      proof_id: 'revocation-runtime-valid',
      oracle_id: 'revocation-oracle-main',
      epoch_id: 'revocation-epoch-42',
      epoch_root: '3333333333333333333333333333333333333333333333333333333333333333',
      sequence: 42,
      fetched_at: '2026-06-10T00:00:00Z',
      max_staleness_ms: 5000,
      revoked_leaf_result: false,
      signature: 'sig-revocation-runtime-valid',
    })
    const sandboxAttestationJson = JSON.stringify({
      schema: 'chio.runtime.sandbox-attestation.v1',
      attestation_id: 'sandbox-runtime-valid',
      tool_server_id: 'tool-server-payments',
      tool_instance_id: 'tool-instance-001',
      tool_manifest_digest: '1111111111111111111111111111111111111111111111111111111111111111',
      sandbox_profile_digest: '4444444444444444444444444444444444444444444444444444444444444444',
      egress_policy_digest: '5555555555555555555555555555555555555555555555555555555555555555',
      started_at: '2026-06-10T00:00:00Z',
      expires_at: '2026-06-10T00:05:00Z',
      attester: 'chio-sandbox-attester',
      signature: 'sig-sandbox-runtime-valid',
    })
    const toolServerAckJson = JSON.stringify({
      schema: 'chio.runtime.tool-server-ack.v1',
      ack_id: 'ack-runtime-valid',
      lease_id: 'lease-runtime-valid',
      tool_server_id: 'tool-server-payments',
      tool_instance_id: 'tool-instance-001',
      sandbox_attestation_ref: 'sandbox-runtime-valid',
      nonce: 'nonce-runtime-valid',
      terminal_status: 'allowed_executed',
      issued_at: '2026-06-10T00:00:02Z',
      signature: 'sig-ack-runtime-valid',
    })
    const executionLeaseDigest = await sha256Hex(executionLeaseJson)
    const revocationFreshnessDigest = await sha256Hex(revocationFreshnessJson)
    const sandboxAttestationDigest = await sha256Hex(sandboxAttestationJson)
    const toolServerAckDigest = await sha256Hex(toolServerAckJson)
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-runtime-valid',
        fixture_id: 'runtime-security-valid-side-effecting-call',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'runtime-verifier-digest',
          schema: 'chio.transaction.runtime-security-report.v1',
        },
        artifacts: [
          {
            path: 'execution-lease.json',
            sha256: executionLeaseDigest,
            schema: 'chio.runtime.execution-lease.v1',
            renderer_hint: 'execution-lease',
            participates_in_primary_verdict: true,
          },
          {
            path: 'revocation-freshness-proof.json',
            sha256: revocationFreshnessDigest,
            schema: 'chio.runtime.revocation-freshness-proof.v1',
            renderer_hint: 'revocation-freshness-proof',
            participates_in_primary_verdict: true,
          },
          {
            path: 'sandbox-attestation.json',
            sha256: sandboxAttestationDigest,
            schema: 'chio.runtime.sandbox-attestation.v1',
            renderer_hint: 'sandbox-attestation',
            participates_in_primary_verdict: true,
          },
          {
            path: 'tool-server-ack.json',
            sha256: toolServerAckDigest,
            schema: 'chio.runtime.tool-server-ack.v1',
            renderer_hint: 'tool-server-ack',
            participates_in_primary_verdict: true,
          },
        ],
        claims: [
          {
            claim_id: 'claim.runtime.execution_lease_valid',
            required_artifacts: ['execution-lease.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.runtime.revocation_fresh_at_dispatch',
            required_artifacts: ['revocation-freshness-proof.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.runtime.sandbox_attestation_matched',
            required_artifacts: ['sandbox-attestation.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.runtime.tool_server_ack_bound',
            required_artifacts: ['tool-server-ack.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-runtime-valid',
        fixture_id: 'runtime-security-valid-side-effecting-call',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'runtime-verifier-digest',
          schema: 'chio.transaction.runtime-security-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.runtime.execution_lease_valid',
            source: 'execution-lease.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.runtime.revocation_fresh_at_dispatch',
            source: 'revocation-freshness-proof.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.runtime.sandbox_attestation_matched',
            source: 'sandbox-attestation.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.runtime.tool_server_ack_bound',
            source: 'tool-server-ack.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.transaction.runtime-security-report.v1',
        id: 'runtime-security-report-runtime-passport-valid',
        issued_at: '2026-06-10T00:00:00Z',
        verdict: 'verified',
        passport_id: 'runtime-passport-valid',
        verified_claims: [
          'claim.runtime.execution_lease_valid',
          'claim.runtime.revocation_fresh_at_dispatch',
          'claim.runtime.sandbox_attestation_matched',
          'claim.runtime.tool_server_ack_bound',
        ],
      }),
      '/execution-lease.json': { ok: true, text: async () => executionLeaseJson },
      '/revocation-freshness-proof.json': { ok: true, text: async () => revocationFreshnessJson },
      '/sandbox-attestation.json': { ok: true, text: async () => sandboxAttestationJson },
      '/tool-server-ack.json': { ok: true, text: async () => toolServerAckJson },
      '/proof-room-fixture-catalog.json': jsonResponse({}, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Runtime Enforcement')

    expect(fetchMock).toHaveBeenCalledWith('/execution-lease.json')
    expect(fetchMock).toHaveBeenCalledWith('/revocation-freshness-proof.json')
    expect(fetchMock).toHaveBeenCalledWith('/sandbox-attestation.json')
    expect(fetchMock).toHaveBeenCalledWith('/tool-server-ack.json')
    expect(container.textContent).toContain('lease-runtime-valid')
    expect(container.textContent).toContain('network-write')
    expect(container.textContent).toContain('revocation-epoch-42')
    expect(container.textContent).toContain('revoked false')
    expect(container.textContent).toContain('sandbox-runtime-valid')
    expect(container.textContent).toContain('chio-sandbox-attester')
    expect(container.textContent).toContain('ack-runtime-valid')
    expect(container.textContent).toContain('allowed_executed')
    expect(container.textContent).toContain('nonce-runtime-valid')
    expect(container.textContent).toContain('claim.runtime.tool_server_ack_bound')
  })

  it('renders manifest-bound risk comptroller details from the Proof Room artifact', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const riskReportJson = JSON.stringify({
      schema: 'chio.risk.comptroller-report.v1',
      id: 'risk-comptroller-enterprise-valid',
      facility: {
        facility_id: 'facility-enterprise-valid',
        state: 'settlement_matched',
        capital_currency: 'USD',
        capital_units: 10000,
        reserve_currency: 'USD',
        reserve_units: 1200,
        reserve_ref: 'reserve-enterprise-valid',
      },
      coverage: {
        coverage_id: 'coverage-enterprise-valid',
        order_id: 'order-commerce-001',
        subject: 'did:chio:buyer-enterprise',
        currency: 'USD',
        exposure_units: 5000,
        reserve_ref: 'reserve-enterprise-valid',
        status: 'bound',
      },
      reconciliation: {
        order_id: 'order-commerce-001',
        currency: 'USD',
        exposure_units: 5000,
        reserve_units: 1200,
        consumed_reserve_units: 0,
        payout_units: 0,
        settlement_units: 0,
        status: 'balanced',
      },
      reserve_ledger: [
        {
          entry_id: 'claim-payout-reserve-enterprise-valid',
          receipt_ref: 'risk-receipt-counterparty-bound',
          lane: 'claim_payout',
          reserve_ref: 'reserve-enterprise-valid',
          claim_id: 'claim-enterprise-covered',
          currency: 'USD',
          units: 600,
          settlement_ref: 'settlement-enterprise-valid',
        },
      ],
      sanction_reserve_ledger: [
        {
          entry_id: 'sanction-market-slash-enterprise-valid',
          bridge_id: 'sanction-bridge-enterprise-valid',
          lane: 'market_slash',
          receipt_ref: 'risk-receipt-market-slash-bridge',
          reserve_ref: 'reserve-enterprise-valid',
          claim_id: 'claim-enterprise-covered',
          currency: 'USD',
          units: 600,
          settlement_ref: 'settlement-enterprise-valid',
          authority_receipt_ref: 'approval-case',
          evidence_ref: 'data-governance-report',
          jurisdiction_ref: 'jurisdiction-enterprise-valid',
        },
      ],
    })
    const riskReportDigest = await sha256Hex(riskReportJson)
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-enterprise-autonomous-commerce',
        fixture_id: 'enterprise-autonomous-commerce',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'enterprise-verifier-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        artifacts: [
          {
            path: 'risk-comptroller-report.json',
            sha256: riskReportDigest,
            schema: 'chio.risk.comptroller-report.v1',
            renderer_hint: 'risk-comptroller-report',
            participates_in_primary_verdict: true,
          },
        ],
        claims: [
          {
            claim_id: 'claim.risk.comptroller_report_bound',
            required_artifacts: ['risk-comptroller-report.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-enterprise-autonomous-commerce',
        fixture_id: 'enterprise-autonomous-commerce',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'enterprise-verifier-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.risk.comptroller_report_bound',
            source: 'risk-comptroller-report.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.transaction.verifier-report.v1',
        id: 'verifier-report-enterprise-autonomous-commerce',
        verdict: 'verified',
        verified_claims: ['claim.risk.comptroller_report_bound'],
      }),
      '/risk-comptroller-report.json': {
        ok: true,
        text: async () => riskReportJson,
        json: async () => JSON.parse(riskReportJson),
      },
      '/proof-room-fixture-catalog.json': jsonResponse({}, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'facility-enterprise-valid')

    expect(fetchMock).toHaveBeenCalledWith('/risk-comptroller-report.json')
    expect(container.textContent).toContain('Risk Comptroller')
    expect(container.textContent).toContain('settlement_matched')
    expect(container.textContent).toContain('reserve-enterprise-valid')
    expect(container.textContent).toContain('coverage-enterprise-valid')
    expect(container.textContent).toContain('balanced')
    expect(container.textContent).toContain('claim_payout')
    expect(container.textContent).toContain('risk-receipt-counterparty-bound')
    expect(container.textContent).toContain('Sanction Reserve Ledger')
    expect(container.textContent).toContain('sanction-bridge-enterprise-valid')
    expect(container.textContent).toContain('jurisdiction-enterprise-valid')
  })

  it('rejects served risk comptroller reports with unsupported schema', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const riskReportJson = JSON.stringify({
      schema: 'chio.risk.unregistered-comptroller-report.v1',
      id: 'risk-comptroller-unsupported-schema',
      facility: {
        facility_id: 'facility-unsupported-schema',
        state: 'settlement_matched',
        reserve_ref: 'reserve-unsupported-schema',
      },
    })
    const riskReportDigest = await sha256Hex(riskReportJson)
    mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-risk-schema-boundary',
        fixture_id: 'risk-schema-boundary',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'risk-verifier-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        artifacts: [
          {
            path: 'risk-comptroller-report.json',
            sha256: riskReportDigest,
            schema: 'chio.risk.comptroller-report.v1',
            renderer_hint: 'risk-comptroller-report',
            participates_in_primary_verdict: true,
          },
        ],
        claims: [
          {
            claim_id: 'claim.risk.comptroller_report_bound',
            required_artifacts: ['risk-comptroller-report.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-risk-schema-boundary',
        fixture_id: 'risk-schema-boundary',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'risk-verifier-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.risk.comptroller_report_bound',
            source: 'risk-comptroller-report.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.transaction.verifier-report.v1',
        id: 'verifier-report-risk-schema-boundary',
        verdict: 'verified',
        verified_claims: ['claim.risk.comptroller_report_bound'],
      }),
      '/risk-comptroller-report.json': textResponse(riskReportJson),
      '/proof-room-fixture-catalog.json': jsonResponse(null, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Proof Room load failed')

    expect(container.textContent).toContain('served risk comptroller report has unsupported schema')
    expect(container.textContent).not.toContain('risk-comptroller-unsupported-schema')
  })

  it('renders manifest-bound enterprise export evidence from Proof Room artifacts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const exportBundleJson = JSON.stringify({
      schema: 'chio.enterprise.evidence-export-bundle.v1',
      id: 'evidence-export-enterprise-valid',
      issued_at: '2026-06-10T00:00:00Z',
      passport_id: 'passport-enterprise-valid',
      risk_comptroller_report_ref: 'risk-comptroller-enterprise-valid',
      approval_case_ref: 'approval-case-enterprise-valid',
      bundle_digest: '4b77ac58cde860e81faca2e4eed641f7dbf44febe6200aa3a3d6aab369e070f7',
      artifacts: [
        {
          role: 'transaction_passport',
          path: 'transaction-passport-export.json',
          sha256: '4946ad8e5db82236a5c3c6a372340c786db1b78b0d590a45c7632469101528e7',
        },
        {
          role: 'data_governance_report',
          path: 'data-governance-report.json',
          sha256: 'c2f94c5995b13409b3712e9ab62b53decef273324a244c4e3d3efaa66e751ef5',
        },
      ],
    })
    const governanceJson = JSON.stringify({
      schema: 'chio.enterprise.data-governance-report.v1',
      id: 'data-governance-enterprise-valid',
      issued_at: '2026-06-10T00:00:00Z',
      passport_id: 'passport-enterprise-valid',
      risk_comptroller_report_ref: 'risk-comptroller-enterprise-valid',
      allowed_regions: ['US'],
      observed_region: 'US',
      retention_class: 'audit-365d',
      legal_hold_status: 'not_held',
      redaction_profile_ref: 'redaction-profile-enterprise-valid',
      disclosure_capsule_ref: 'disclosure-report-enterprise-valid',
      leakage_ledger_ref: 'leakage-ledger-enterprise-valid',
      field_classifications: [
        {
          field: 'customer_email',
          classification: 'pii',
          export_action: 'redacted',
        },
        {
          field: 'order_id',
          classification: 'business',
          export_action: 'disclosed',
        },
      ],
    })
    const telemetryJson = JSON.stringify({
      schema: 'chio.enterprise.telemetry-projection.v1',
      id: 'telemetry-enterprise-valid',
      issued_at: '2026-06-10T00:00:00Z',
      passport_id: 'passport-enterprise-valid',
      risk_comptroller_report_ref: 'risk-comptroller-enterprise-valid',
      events: [
        {
          event_id: 'allow-event',
          event_kind: 'allow',
          artifact_ref: 'transaction-passport-export.json',
          artifact_sha256: '4946ad8e5db82236a5c3c6a372340c786db1b78b0d590a45c7632469101528e7',
        },
        {
          event_id: 'denied-guard-event',
          event_kind: 'denied_guard',
          artifact_ref: 'data-governance-report.json',
          artifact_sha256: 'c2f94c5995b13409b3712e9ab62b53decef273324a244c4e3d3efaa66e751ef5',
        },
      ],
    })
    const approvalJson = JSON.stringify({
      schema: 'chio.enterprise.approval-case.v1',
      id: 'approval-case-enterprise-valid',
      issued_at: '2026-06-10T00:00:00Z',
      passport_id: 'passport-enterprise-valid',
      risk_comptroller_report_ref: 'risk-comptroller-enterprise-valid',
      decision: 'approved',
      decision_subject: 'evidence-export',
      approvers: ['did:chio:enterprise-reviewer'],
      required_quorum: 1,
      expires_at: '2026-06-11T00:00:00Z',
    })
    const controlMapJson = JSON.stringify({
      schema: 'chio.enterprise.control-evidence-map.v1',
      id: 'control-map-enterprise-valid',
      issued_at: '2026-06-10T00:00:00Z',
      passport_id: 'passport-enterprise-valid',
      risk_comptroller_report_ref: 'risk-comptroller-enterprise-valid',
      controls: [
        {
          control_id: 'data-minimization',
          control_family: 'internal-proof',
          claim_ref: 'claim.enterprise.data_governance_bound',
          gate_ref: 'data-governance-report',
        },
        {
          control_id: 'sensitive-export-approval',
          control_family: 'internal-proof',
          claim_ref: 'claim.enterprise.export_approval_bound',
          gate_ref: 'approval-case',
        },
      ],
    })
    const exportBundleDigest = await sha256Hex(exportBundleJson)
    const governanceDigest = await sha256Hex(governanceJson)
    const telemetryDigest = await sha256Hex(telemetryJson)
    const approvalDigest = await sha256Hex(approvalJson)
    const controlMapDigest = await sha256Hex(controlMapJson)
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-enterprise-autonomous-commerce',
        fixture_id: 'enterprise-autonomous-commerce',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'enterprise-verifier-digest',
          schema: 'chio.enterprise.export-verifier-report.v1',
        },
        artifacts: [
          {
            path: 'evidence-export-bundle.json',
            sha256: exportBundleDigest,
            schema: 'chio.enterprise.evidence-export-bundle.v1',
            renderer_hint: 'enterprise-evidence-export-bundle',
            participates_in_primary_verdict: true,
          },
          {
            path: 'data-governance-report.json',
            sha256: governanceDigest,
            schema: 'chio.enterprise.data-governance-report.v1',
            renderer_hint: 'enterprise-data-governance-report',
            participates_in_primary_verdict: true,
          },
          {
            path: 'telemetry-projection.json',
            sha256: telemetryDigest,
            schema: 'chio.enterprise.telemetry-projection.v1',
            renderer_hint: 'enterprise-telemetry-projection',
            participates_in_primary_verdict: true,
          },
          {
            path: 'approval-case.json',
            sha256: approvalDigest,
            schema: 'chio.enterprise.approval-case.v1',
            renderer_hint: 'enterprise-approval-case',
            participates_in_primary_verdict: true,
          },
          {
            path: 'control-evidence-map.json',
            sha256: controlMapDigest,
            schema: 'chio.enterprise.control-evidence-map.v1',
            renderer_hint: 'enterprise-control-evidence-map',
            participates_in_primary_verdict: true,
          },
        ],
        claims: [
          {
            claim_id: 'claim.enterprise.evidence_export_digest_bound',
            required_artifacts: ['evidence-export-bundle.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.enterprise.data_governance_bound',
            required_artifacts: ['data-governance-report.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.enterprise.telemetry_projection_bound',
            required_artifacts: ['telemetry-projection.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.enterprise.export_approval_bound',
            required_artifacts: ['approval-case.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.enterprise.control_map_bound',
            required_artifacts: ['control-evidence-map.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-enterprise-autonomous-commerce',
        fixture_id: 'enterprise-autonomous-commerce',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'enterprise-verifier-digest',
          schema: 'chio.enterprise.export-verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.enterprise.evidence_export_digest_bound',
            source: 'evidence-export-bundle.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.enterprise.data_governance_bound',
            source: 'data-governance-report.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.enterprise.telemetry_projection_bound',
            source: 'telemetry-projection.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.enterprise.export_approval_bound',
            source: 'approval-case.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.enterprise.control_map_bound',
            source: 'control-evidence-map.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.enterprise.export-verifier-report.v1',
        id: 'verifier-report-enterprise-autonomous-commerce',
        verdict: 'verified',
        verified_claims: [
          'claim.enterprise.evidence_export_digest_bound',
          'claim.enterprise.data_governance_bound',
          'claim.enterprise.telemetry_projection_bound',
          'claim.enterprise.export_approval_bound',
          'claim.enterprise.control_map_bound',
        ],
      }),
      '/evidence-export-bundle.json': { ok: true, text: async () => exportBundleJson },
      '/data-governance-report.json': { ok: true, text: async () => governanceJson },
      '/telemetry-projection.json': { ok: true, text: async () => telemetryJson },
      '/approval-case.json': { ok: true, text: async () => approvalJson },
      '/control-evidence-map.json': { ok: true, text: async () => controlMapJson },
      '/proof-room-fixture-catalog.json': jsonResponse({}, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Enterprise Export')

    expect(fetchMock).toHaveBeenCalledWith('/evidence-export-bundle.json')
    expect(fetchMock).toHaveBeenCalledWith('/data-governance-report.json')
    expect(fetchMock).toHaveBeenCalledWith('/telemetry-projection.json')
    expect(fetchMock).toHaveBeenCalledWith('/approval-case.json')
    expect(fetchMock).toHaveBeenCalledWith('/control-evidence-map.json')
    expect(container.textContent).toContain('evidence-export-enterprise-valid')
    expect(container.textContent).toContain('audit-365d')
    expect(container.textContent).toContain('customer_email')
    expect(container.textContent).toContain('redacted')
    expect(container.textContent).toContain('allow-event')
    expect(container.textContent).toContain('denied_guard')
    expect(container.textContent).toContain('approval-case-enterprise-valid')
    expect(container.textContent).toContain('did:chio:enterprise-reviewer')
    expect(container.textContent).toContain('data-minimization')
    expect(container.textContent).toContain('sensitive-export-approval')
  })

  it('renders manifest-bound Trust Market context from Proof Room artifacts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const discoveryJson = JSON.stringify({
      schema: 'chio.commerce.provider-discovery-snapshot.v1',
      id: 'discovery-trust-market-valid',
      passport_id: 'passport-trust-market-valid',
      order_id: 'order-commerce-001',
      market_scope: 'bounded-autonomous-commerce',
      provider_candidates: [
        {
          subject: 'did:chio:provider-alpha',
          jurisdiction_ref: 'jurisdiction-trust-market-valid',
          excluded: false,
        },
        {
          subject: 'did:chio:provider-beta',
          jurisdiction_ref: 'jurisdiction-trust-market-valid',
          excluded: false,
        },
      ],
      discovery_authority_ref: 'did:chio:market-curator',
    })
    const selectionJson = JSON.stringify({
      schema: 'chio.commerce.provider-selection-report.v1',
      id: 'selection-trust-market-valid',
      passport_id: 'passport-trust-market-valid',
      order_id: 'order-commerce-001',
      discovery_snapshot_ref: 'discovery-trust-market-valid',
      selected_provider_subject: 'did:chio:provider-alpha',
      scorecard_ref: 'scorecard-trust-market-valid',
      sla_commitment_ref: 'sla-commitment-trust-market-valid',
      risk_report_ref: 'risk-comptroller-market-valid',
      selection_reason_codes: ['highest_local_score', 'sla_available'],
      ranking_results: [
        {
          provider_subject: 'did:chio:provider-alpha',
          rank: 1,
          total_score: 92,
        },
        {
          provider_subject: 'did:chio:provider-beta',
          rank: 2,
          total_score: 81,
        },
      ],
    })
    const scorecardJson = JSON.stringify({
      schema: 'chio.trust.scorecard-snapshot.v1',
      id: 'scorecard-trust-market-valid',
      subject: 'did:chio:provider-alpha',
      scope: 'local-policy',
      component_scores: [
        {
          component: 'native_reputation',
          score: 92,
          weight: 40,
          evidence_ref: 'reputation-native-alpha',
          stale: false,
        },
        {
          component: 'portable_reputation',
          score: 88,
          weight: 30,
          evidence_ref: 'reputation-import-trust-market-valid',
          stale: false,
        },
      ],
      computed_score: 92,
      downgrade_reasons: [],
    })
    const reputationJson = JSON.stringify({
      schema: 'chio.trust.reputation-import-report.v1',
      id: 'reputation-import-trust-market-valid',
      subject: 'did:chio:provider-alpha',
      source_network: 'federated-commerce-network',
      issuer: 'did:chio:federation-root',
      local_weight: 30,
      import_verdict: 'accepted',
      usage: 'scoring_input',
    })
    const slaJson = JSON.stringify({
      schema: 'chio.commerce.sla-commitment.v1',
      id: 'sla-commitment-trust-market-valid',
      order_id: 'order-commerce-001',
      provider_subject: 'did:chio:provider-alpha',
      buyer_subject: 'did:chio:buyer-acme',
      service_scope: 'bounded-shopping-task',
      collateral_position_ref: 'collateral-trust-market-valid',
      guarantee_decision_ref: 'guarantee-trust-market-valid',
      metric_definitions: [
        {
          metric: 'completion_time_minutes',
          target: 30,
          unit: 'minutes',
        },
      ],
    })
    const slaPerformanceJson = JSON.stringify({
      schema: 'chio.commerce.sla-performance-report.v1',
      id: 'sla-performance-trust-market-valid',
      sla_ref: 'sla-commitment-trust-market-valid',
      order_id: 'order-commerce-001',
      provider_subject: 'did:chio:provider-alpha',
      computed_metric_results: [
        {
          metric: 'completion_time_minutes',
          value: 18,
          unit: 'minutes',
          passed: true,
        },
      ],
      breach_verdict: 'none',
    })
    const collateralJson = JSON.stringify({
      schema: 'chio.risk.collateral-position-report.v1',
      id: 'collateral-trust-market-valid',
      subject: 'did:chio:provider-alpha',
      order_id: 'order-commerce-001',
      currency_or_asset: 'USD',
      amount: 1000,
      source_type: 'bond',
      available_amount: 1000,
    })
    const guaranteeJson = JSON.stringify({
      schema: 'chio.risk.guarantee-decision.v1',
      id: 'guarantee-trust-market-valid',
      order_id: 'order-commerce-001',
      provider_subject: 'did:chio:provider-alpha',
      beneficiary_subject: 'did:chio:buyer-acme',
      guarantee_type: 'bounded_sla_remedy',
      maximum_remedy: 500,
      currency: 'USD',
      backing_refs: ['collateral-trust-market-valid'],
      adjudication_jurisdiction_ref: 'jurisdiction-trust-market-valid',
      verdict: 'backed',
    })
    const jurisdictionJson = JSON.stringify({
      schema: 'chio.risk.adjudication-jurisdiction-receipt.v1',
      id: 'jurisdiction-trust-market-valid',
      jurisdiction_id: 'jurisdiction-trust-market-valid',
      order_id: 'order-commerce-001',
      policy_ref: 'jurisdiction-policy-market-valid',
      covered_dispute_types: ['sla_breach', 'guarantee_claim'],
      adjudicator_subjects: ['did:chio:market-adjudicator'],
      slash_authority_refs: ['did:chio:slash-authority'],
    })
    const artifacts = [
      [
        'provider-discovery-snapshot.json',
        'chio.commerce.provider-discovery-snapshot.v1',
        'provider-discovery-snapshot',
        discoveryJson,
      ],
      [
        'provider-selection-report.json',
        'chio.commerce.provider-selection-report.v1',
        'provider-selection-report',
        selectionJson,
      ],
      [
        'trust-scorecard-snapshot.json',
        'chio.trust.scorecard-snapshot.v1',
        'trust-scorecard-snapshot',
        scorecardJson,
      ],
      [
        'reputation-import-report.json',
        'chio.trust.reputation-import-report.v1',
        'reputation-import-report',
        reputationJson,
      ],
      [
        'sla-commitment.json',
        'chio.commerce.sla-commitment.v1',
        'sla-commitment',
        slaJson,
      ],
      [
        'sla-performance-report.json',
        'chio.commerce.sla-performance-report.v1',
        'sla-performance-report',
        slaPerformanceJson,
      ],
      [
        'collateral-position-report.json',
        'chio.risk.collateral-position-report.v1',
        'collateral-position-report',
        collateralJson,
      ],
      [
        'guarantee-decision.json',
        'chio.risk.guarantee-decision.v1',
        'guarantee-decision',
        guaranteeJson,
      ],
      [
        'adjudication-jurisdiction-receipt.json',
        'chio.risk.adjudication-jurisdiction-receipt.v1',
        'adjudication-jurisdiction-receipt',
        jurisdictionJson,
      ],
    ] as const
    const artifactDigests = new Map<string, string>()
    for (const [path, , , json] of artifacts) {
      artifactDigests.set(path, await sha256Hex(json))
    }
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-trust-market-valid',
        fixture_id: 'trust-market-valid',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'trust-market-verifier-digest',
          schema: 'chio.trust-market.context-verifier-report.v1',
        },
        artifacts: artifacts.map(([path, schema, rendererHint]) => ({
          path,
          sha256: artifactDigests.get(path),
          schema,
          renderer_hint: rendererHint,
          participates_in_primary_verdict: true,
        })),
        claims: [
          {
            claim_id: 'claim.trust_market.provider_discovery_bound',
            required_artifacts: ['provider-discovery-snapshot.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.trust_market.provider_selection_bound',
            required_artifacts: ['provider-selection-report.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.trust_market.local_scorecard_bound',
            required_artifacts: ['trust-scorecard-snapshot.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.trust_market.sla_bound',
            required_artifacts: ['sla-commitment.json', 'sla-performance-report.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.trust_market.guarantee_backed',
            required_artifacts: ['guarantee-decision.json', 'collateral-position-report.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.trust_market.adjudication_jurisdiction_bound',
            required_artifacts: ['adjudication-jurisdiction-receipt.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-trust-market-valid',
        fixture_id: 'trust-market-valid',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'trust-market-verifier-digest',
          schema: 'chio.trust-market.context-verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.trust_market.provider_discovery_bound',
            source: 'provider-discovery-snapshot.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.trust_market.provider_selection_bound',
            source: 'provider-selection-report.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.trust_market.local_scorecard_bound',
            source: 'trust-scorecard-snapshot.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.trust_market.sla_bound',
            source: 'sla-commitment.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.trust_market.guarantee_backed',
            source: 'guarantee-decision.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.trust_market.adjudication_jurisdiction_bound',
            source: 'adjudication-jurisdiction-receipt.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.trust-market.context-verifier-report.v1',
        id: 'trust-market-verifier-report-valid',
        verdict: 'verified',
        verified_claims: [
          'claim.trust_market.provider_discovery_bound',
          'claim.trust_market.provider_selection_bound',
          'claim.trust_market.local_scorecard_bound',
          'claim.trust_market.sla_bound',
          'claim.trust_market.guarantee_backed',
          'claim.trust_market.adjudication_jurisdiction_bound',
        ],
      }),
      ...Object.fromEntries(
        artifacts.map(([path, , , json]) => [`/${path}`, { ok: true, text: async () => json }]),
      ),
      '/proof-room-fixture-catalog.json': jsonResponse({}, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Trust Market Context')

    for (const [path] of artifacts) {
      expect(fetchMock).toHaveBeenCalledWith(`/${path}`)
    }
    expect(container.textContent).toContain('bounded-autonomous-commerce')
    expect(container.textContent).toContain('did:chio:provider-alpha')
    expect(container.textContent).toContain('highest_local_score')
    expect(container.textContent).toContain('local-policy')
    expect(container.textContent).toContain('reputation-import-trust-market-valid')
    expect(container.textContent).toContain('completion_time_minutes')
    expect(container.textContent).toContain('18 minutes')
    expect(container.textContent).toContain('collateral-trust-market-valid')
    expect(container.textContent).toContain('1000 USD')
    expect(container.textContent).toContain('guarantee-trust-market-valid')
    expect(container.textContent).toContain('backed')
    expect(container.textContent).toContain('jurisdiction-trust-market-valid')
  })

  it('renders manifest-bound commerce order evidence from Proof Room artifacts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const orderContextJson = JSON.stringify({
      schema: 'chio.commerce.order-context.v1',
      id: 'order-context-commerce-001',
      order_id: 'order-commerce-001',
      buyer_subject: 'buyer:demo-cafe-customer',
      agent_subject: 'agent:single-call-authority',
      merchant_subject: 'merchant:stripe:coffee-shop',
      quote_id: 'quote-commerce-001',
      quote_amount_minor: 4200,
      quote_currency: 'USD',
      current_state: 'completed',
    })
    const paymentLifecycleJson = JSON.stringify({
      schema: 'chio.commerce.payment-lifecycle.v1',
      id: 'payment-lifecycle-commerce-001',
      order_id: 'order-commerce-001',
      merchant_subject: 'merchant:stripe:coffee-shop',
      psp: 'stripe-shaped-offline',
      payment_intent_id: 'pi_commerce_001',
      amount_minor: 4200,
      currency: 'USD',
      payment_status: 'succeeded',
    })
    const eventLogJson = JSON.stringify({
      schema: 'chio.commerce.event-log.v1',
      id: 'event-log-commerce-001',
      order_id: 'order-commerce-001',
      events: [
        {
          event_id: 'event-commerce-001-intent',
          transition: 'record_intent',
          prior_state: 'none',
          next_state: 'intent_recorded',
          authority_receipt_ref: 'receipt-intent-commerce-001',
        },
        {
          event_id: 'event-commerce-001-complete',
          transition: 'complete_order',
          prior_state: 'settlement_reconciled',
          next_state: 'completed',
          authority_receipt_ref: 'receipt-complete-commerce-001',
        },
      ],
    })
    const orderContextDigest = await sha256Hex(orderContextJson)
    const paymentLifecycleDigest = await sha256Hex(paymentLifecycleJson)
    const eventLogDigest = await sha256Hex(eventLogJson)
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-commerce-offline-psp',
        fixture_id: 'commerce-offline-psp',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'commerce-verifier-digest',
          schema: 'chio.commerce.order-passport.v1',
        },
        artifacts: [
          {
            path: 'order-context.json',
            sha256: orderContextDigest,
            schema: 'chio.commerce.order-context.v1',
            renderer_hint: 'commerce-order-context',
            participates_in_primary_verdict: true,
          },
          {
            path: 'payment-lifecycle.json',
            sha256: paymentLifecycleDigest,
            schema: 'chio.commerce.payment-lifecycle.v1',
            renderer_hint: 'commerce-payment-lifecycle',
            participates_in_primary_verdict: true,
          },
          {
            path: 'event-log.json',
            sha256: eventLogDigest,
            schema: 'chio.commerce.event-log.v1',
            renderer_hint: 'commerce-event-log',
            participates_in_primary_verdict: true,
          },
        ],
        claims: [
          {
            claim_id: 'claim.commerce.order_replay_consistent',
            required_artifacts: ['order-context.json', 'event-log.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.commerce.payment_lifecycle_bound',
            required_artifacts: ['payment-lifecycle.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-commerce-offline-psp',
        fixture_id: 'commerce-offline-psp',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'commerce-verifier-digest',
          schema: 'chio.commerce.order-passport.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.commerce.order_replay_consistent',
            source: 'order-context.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.commerce.payment_lifecycle_bound',
            source: 'payment-lifecycle.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.commerce.order-passport.v1',
        id: 'commerce-order-passport-order-commerce-001',
        verdict: 'verified',
        order_id: 'order-commerce-001',
        current_state: 'completed',
        verified_claims: [
          'claim.commerce.order_replay_consistent',
          'claim.commerce.payment_lifecycle_bound',
        ],
      }),
      '/order-context.json': {
        ok: true,
        text: async () => orderContextJson,
        json: async () => JSON.parse(orderContextJson),
      },
      '/payment-lifecycle.json': {
        ok: true,
        text: async () => paymentLifecycleJson,
        json: async () => JSON.parse(paymentLifecycleJson),
      },
      '/event-log.json': {
        ok: true,
        text: async () => eventLogJson,
        json: async () => JSON.parse(eventLogJson),
      },
      '/proof-room-fixture-catalog.json': jsonResponse({}, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Commerce Order')

    expect(fetchMock).toHaveBeenCalledWith('/order-context.json')
    expect(fetchMock).toHaveBeenCalledWith('/payment-lifecycle.json')
    expect(fetchMock).toHaveBeenCalledWith('/event-log.json')
    expect(container.textContent).toContain('order-commerce-001')
    expect(container.textContent).toContain('completed')
    expect(container.textContent).toContain('merchant:stripe:coffee-shop')
    expect(container.textContent).toContain('4200 USD')
    expect(container.textContent).toContain('succeeded')
    expect(container.textContent).toContain('stripe-shaped-offline')
    expect(container.textContent).toContain('record_intent')
    expect(container.textContent).toContain('complete_order')
  })

  it('renders manifest-bound public settlement proof evidence from Proof Room artifacts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const settlementProofJson = JSON.stringify({
      schema: 'chio.web3-settlement-proof-bundle.v1',
      bundle_id: 'web3-settlement-proof-public-valid',
      transaction_passport_id: 'passport-public-settlement-valid',
      commerce_order_id: 'order-public-settlement-valid',
      chain_id: 'eip155:8453',
      required_confirmations: 20,
      observed_confirmations: 24,
      dispute_posture: 'undisputed',
      settlement_receipt: {
        execution_receipt_id: 'receipt-web3-1',
        lifecycle_state: 'settled',
        settlement_reference: 'settlement-web3-1',
        settled_amount: {
          units: 150,
          currency: 'USD',
        },
        observed_execution: {
          externalReferenceId:
            '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
          observedAt: 1743292860,
        },
        oracle_evidence: {
          source: 'chainlink',
          base: 'ETH',
          quote: 'USD',
        },
      },
      chain_snapshot: {
        observed_block_number: 12345678,
        latest_block_number: 12345700,
        registry_root: '0xfba90da7db4859cf33cd97a64b2ce07f244c8fcafe51c19ddd67b03c8490c3eb',
        escrow: {
          escrow_id: 'escrow-web3-1',
          escrow_contract: '0x1000000000000000000000000000000000000002',
          beneficiary_address: '0x2222222222222222222222222222222222222222',
          locked_amount: {
            units: 150,
            currency: 'USD',
          },
          released_amount: {
            units: 150,
            currency: 'USD',
          },
        },
        bond: {
          bond_vault_contract: '0x1000000000000000000000000000000000000003',
          posted_amount: {
            units: 150,
            currency: 'USD',
          },
          minimum_required_amount: {
            units: 150,
            currency: 'USD',
          },
        },
      },
      dispute_snapshot: {
        dispute_id: 'dispute-public-settlement-none',
        posture: 'undisputed',
        open_dispute_count: 0,
      },
    })
    const settlementProofDigest = await sha256Hex(settlementProofJson)
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-public-settlement',
        fixture_id: 'public-settlement-offline-finality',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'settlement-verifier-digest',
          schema: 'chio.public-settlement-verifier-report.v1',
        },
        artifacts: [
          {
            path: 'settlement-proof-bundle.json',
            sha256: settlementProofDigest,
            schema: 'chio.web3-settlement-proof-bundle.v1',
            renderer_hint: 'public-settlement-proof-bundle',
            participates_in_primary_verdict: true,
          },
        ],
        claims: [
          {
            claim_id: 'claim.public_settlement.finality_verified',
            required_artifacts: ['settlement-proof-bundle.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.public_settlement.dispute_posture_bound',
            required_artifacts: ['settlement-proof-bundle.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-public-settlement',
        fixture_id: 'public-settlement-offline-finality',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'settlement-verifier-digest',
          schema: 'chio.public-settlement-verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.public_settlement.finality_verified',
            source: 'settlement-proof-bundle.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.public_settlement.dispute_posture_bound',
            source: 'settlement-proof-bundle.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.public-settlement-verifier-report.v1',
        id: 'public-settlement-verifier-report-web3-settlement-proof-public-valid',
        verdict: 'verified',
        bundle_id: 'web3-settlement-proof-public-valid',
        transaction_passport_id: 'passport-public-settlement-valid',
        commerce_order_id: 'order-public-settlement-valid',
        recomputed_settlement_state: 'settled',
        chain_context: {
          chain_id: 'eip155:8453',
          settlement_path: 'merkle_proof',
          settlement_reference: 'settlement-web3-1',
          observed_block_number: 12345678,
          registry_root: '0xfba90da7db4859cf33cd97a64b2ce07f244c8fcafe51c19ddd67b03c8490c3eb',
          escrow_id: 'escrow-web3-1',
          bond_vault_contract: '0x1000000000000000000000000000000000000003',
          posted_bond_amount: {
            units: 150,
            currency: 'USD',
          },
          minimum_bond_amount: {
            units: 150,
            currency: 'USD',
          },
          block_hash: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          anchor_tx_hash: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          settlement_tx_hash: '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
          beneficiary_address: '0x2222222222222222222222222222222222222222',
          beneficiary_chio_identity: 'did:chio:91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a',
        },
        public_witness: {
          witness_id: 'public-witness-web3-settlement-proof-public-valid',
          mode: 'verified_cache',
          body_hash: '596b565fcf31901fe72aedf144970456ab16da13803d856fdd08cec3906b9a6f',
          observed_at: 1743293500,
        },
        finality_decision: {
          status: 'final',
          required_confirmations: 20,
          observed_confirmations: 24,
        },
        dispute_context: {
          dispute_id: 'dispute-public-settlement-none',
          posture: 'undisputed',
          observed_at: 1743293460,
          challenge_window_secs: 600,
          window_closed_at: 1743293460,
          open_dispute_count: 0,
        },
        dispute_posture: 'undisputed',
        verified_claims: [
          'claim.public_settlement.finality_verified',
          'claim.public_settlement.dispute_posture_bound',
        ],
      }),
      '/settlement-proof-bundle.json': {
        ok: true,
        text: async () => settlementProofJson,
        json: async () => JSON.parse(settlementProofJson),
      },
      '/proof-room-fixture-catalog.json': jsonResponse(
        {},
        { ok: false, status: 404, statusText: 'Not Found' },
      ),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Public Settlement')

    expect(fetchMock).toHaveBeenCalledWith('/settlement-proof-bundle.json')
    expect(container.textContent).toContain('web3-settlement-proof-public-valid')
    expect(container.textContent).toContain('order-public-settlement-valid')
    expect(container.textContent).toContain('eip155:8453')
    expect(container.textContent).toContain('24 of 20 confirmations')
    expect(container.textContent).toContain('escrow-web3-1')
    expect(container.textContent).toContain('150 USD')
    expect(container.textContent).toContain('undisputed')
    expect(container.textContent).toContain('chainlink')
    expect(container.textContent).toContain('Verifier Finality')
    expect(container.textContent).toContain('Verified finality')
    expect(container.textContent).toContain('Supplied finality')
    expect(container.textContent).toContain('Verified chain')
    expect(container.textContent).toContain('Supplied chain')
    expect(container.textContent).toContain('Verified settlement reference')
    expect(container.textContent).toContain('Supplied settlement reference')
    expect(container.textContent).toContain('final')
    expect(container.textContent).toContain('verified_cache')
    expect(container.textContent).toContain('public-witness-web3-settlement-proof-public-valid')
    expect(container.textContent).toContain('merkle_proof')
    expect(container.textContent).toContain(
      '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    )
  })

  it('renders manifest-bound disclosure lineage evidence from Proof Room artifacts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const disclosureCapsuleJson = JSON.stringify({
      schema: 'chio.disclosure.capsule.v1',
      id: 'disclosure-capsule-valid',
      transaction_passport_ref: 'passport-disclosure-lineage-valid',
      privacy_profile_ref: 'privacy-profile-valid',
      lineage_subgraph_ref: 'lineage-subgraph-valid',
      leakage_ledger_ref: 'leakage-ledger-valid',
      disclosed_fields: ['capability_id', 'tool_name'],
      hidden_predicates: [
        {
          predicate_id: 'amount_lte_100',
          kind: 'amount_cap',
          field: 'amount',
          operator: '<=',
          operand: '100',
          unit: 'USD',
          result: true,
          proof_ref: 'selective-disclosure-proof',
          projection_slot: 2,
        },
      ],
    })
    const signedLineageJson = JSON.stringify({
      schema: 'chio.lineage.signed-subgraph.v1',
      id: 'lineage-subgraph-valid',
      transaction_passport_ref: 'passport-disclosure-lineage-valid',
      root_receipt_ids: ['receipt-root'],
      nodes: [
        {
          id: 'receipt-root',
          receipt_ref: 'receipt-root',
          disclosure_state: 'disclosed',
        },
        {
          id: 'receipt-child',
          receipt_ref: 'receipt-child',
          disclosure_state: 'redacted',
        },
      ],
      edges: [
        {
          from: 'receipt-root',
          to: 'receipt-child',
          relation: 'continued',
        },
      ],
      redactions: [
        {
          node_id: 'receipt-child',
          reason: 'privacy_profile',
        },
      ],
      signature:
        'sig-ed25519:e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa:c7985a45677320c42a98141b4a79b284a8a7e79ebaec4385e94231bd107dc8be6ff2c71587c263c315cd4c04eed7e824e6d91b6e766436740a8a51904b6aca06',
    })
    const leakageLedgerJson = JSON.stringify({
      schema: 'chio.disclosure.leakage-ledger.v1',
      id: 'leakage-ledger-valid',
      transaction_passport_ref: 'passport-disclosure-lineage-valid',
      privacy_profile_ref: 'privacy-profile-valid',
      entries: [
        {
          field: 'capability_id',
          leakage_kind: 'disclosed_field',
          allowed_by_profile: true,
        },
        {
          field: 'amount_lte_100',
          leakage_kind: 'hidden_predicate',
          allowed_by_profile: true,
          residual_inference_note: 'predicate reveals capped amount band',
        },
      ],
    })
    const disclosureCapsuleDigest = await sha256Hex(disclosureCapsuleJson)
    const signedLineageDigest = await sha256Hex(signedLineageJson)
    const leakageLedgerDigest = await sha256Hex(leakageLedgerJson)
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-disclosure-lineage',
        fixture_id: 'disclosure-lineage-ledger',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'disclosure-verifier-digest',
          schema: 'chio.disclosure.lineage-verifier-report.v1',
        },
        artifacts: [
          {
            path: 'capsule.json',
            sha256: disclosureCapsuleDigest,
            schema: 'chio.disclosure.capsule.v1',
            renderer_hint: 'disclosure-capsule',
            participates_in_primary_verdict: true,
          },
          {
            path: 'signed-lineage-subgraph.json',
            sha256: signedLineageDigest,
            schema: 'chio.lineage.signed-subgraph.v1',
            renderer_hint: 'signed-lineage-subgraph',
            participates_in_primary_verdict: true,
          },
          {
            path: 'leakage-ledger.json',
            sha256: leakageLedgerDigest,
            schema: 'chio.disclosure.leakage-ledger.v1',
            renderer_hint: 'disclosure-leakage-ledger',
            participates_in_primary_verdict: true,
          },
        ],
        claims: [
          {
            claim_id: 'claim.disclosure.lineage_subgraph_bound',
            required_artifacts: ['signed-lineage-subgraph.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.disclosure.leakage_ledger_complete',
            required_artifacts: ['capsule.json', 'leakage-ledger.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-disclosure-lineage',
        fixture_id: 'disclosure-lineage-ledger',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'disclosure-verifier-digest',
          schema: 'chio.disclosure.lineage-verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.disclosure.lineage_subgraph_bound',
            source: 'signed-lineage-subgraph.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.disclosure.leakage_ledger_complete',
            source: 'leakage-ledger.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.disclosure.lineage-verifier-report.v1',
        id: 'lineage-verifier-report-valid',
        verdict: 'verified',
        verified_claims: [
          'claim.disclosure.lineage_subgraph_bound',
          'claim.disclosure.leakage_ledger_complete',
        ],
      }),
      '/capsule.json': {
        ok: true,
        text: async () => disclosureCapsuleJson,
        json: async () => JSON.parse(disclosureCapsuleJson),
      },
      '/signed-lineage-subgraph.json': {
        ok: true,
        text: async () => signedLineageJson,
        json: async () => JSON.parse(signedLineageJson),
      },
      '/leakage-ledger.json': {
        ok: true,
        text: async () => leakageLedgerJson,
        json: async () => JSON.parse(leakageLedgerJson),
      },
      '/proof-room-fixture-catalog.json': jsonResponse(
        {},
        { ok: false, status: 404, statusText: 'Not Found' },
      ),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Disclosure Lineage')

    expect(fetchMock).toHaveBeenCalledWith('/capsule.json')
    expect(fetchMock).toHaveBeenCalledWith('/signed-lineage-subgraph.json')
    expect(fetchMock).toHaveBeenCalledWith('/leakage-ledger.json')
    expect(container.textContent).toContain('disclosure-capsule-valid')
    expect(container.textContent).toContain('privacy-profile-valid')
    expect(container.textContent).toContain('capability_id')
    expect(container.textContent).toContain('amount_lte_100')
    expect(container.textContent).toContain('lineage-subgraph-valid')
    expect(container.textContent).toContain('receipt-root')
    expect(container.textContent).toContain('redacted')
    expect(container.textContent).toContain('privacy_profile')
    expect(container.textContent).toContain('hidden_predicate')
    expect(container.textContent).toContain('predicate reveals capped amount band')
  })

  it('renders manifest-bound crypto context evidence from Proof Room artifacts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const verificationContextJson = JSON.stringify({
      schema: 'chio.crypto.verification-context.v1',
      context_id: 'crypto-context-buyer-auditor',
      artifact_ref: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      proof_mechanism: 'bbs',
      issuer: 'did:chio:issuer-bbs',
      issuer_key_ref: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      key_state: {
        schema: 'chio.trust.key-state.v1',
        key_ref: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        status: 'active',
        epoch: 7,
        valid_from: 1766000000,
        valid_until: 1766000900,
      },
      algorithm: 'bbs-bls12381-sha256',
      suite: 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_',
      hash_algorithm: 'sha-256',
      canonicalization: 'jcs',
      signature_ref: 'bbs-proof',
      verification_time: 1766000100,
      revocation_snapshot: {
        schema: 'chio.trust.revocation-snapshot.v1',
        snapshot_ref: 'revocation-snapshot-buyer-auditor',
        status: 'fresh',
        issued_at: 1766000050,
        expires_at: 1766000350,
      },
      audience: 'https://auditor.example/chio',
      nonce_hex: '6e6f6e63652d63727970746f2d636f6e74657874',
      nonce_replay_status: 'fresh',
      holder_binding_ref: 'holder:buyer-agent',
      holder_binding_status: 'bound',
      transparency_state: 'anchored',
      presentation_created_at: 1766000080,
    })
    const keyStateJson = JSON.stringify({
      schema: 'chio.trust.key-state.v1',
      key_ref: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'active',
      epoch: 7,
      valid_from: 1766000000,
      valid_until: 1766000900,
    })
    const revocationSnapshotJson = JSON.stringify({
      schema: 'chio.trust.revocation-snapshot.v1',
      snapshot_ref: 'revocation-snapshot-buyer-auditor',
      status: 'fresh',
      issued_at: 1766000050,
      expires_at: 1766000350,
    })
    const privacyProfileJson = JSON.stringify({
      schema: 'chio.disclosure.verifier-privacy-profile.v1',
      profile_id: 'profile-buyer-auditor-context',
      allowed_proof_mechanisms: ['bbs'],
      required_holder_binding: 'holder:buyer-agent',
      allowed_issuer_keys: [
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      ],
      required_key_epoch_min: 7,
      forbidden_key_epochs: [9],
      required_status_freshness_seconds: 300,
      required_audience: 'https://auditor.example/chio',
      nonce_policy: 'no_replay',
      allowed_algorithms: ['bbs-bls12381-sha256'],
      forbidden_algorithms: ['rsa-pkcs1v15-sha1'],
      required_transparency_state: 'anchored',
      max_presentation_age_seconds: 600,
    })
    const transparencyProofJson = JSON.stringify({
      schema: 'chio.transparency.inclusion-proof.v1',
      proof_id: 'transparency-proof-buyer-auditor',
      log_id: 'log:proof-room-transparency',
      artifact_ref: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      root_hash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      leaf_hash: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      tree_size: 8,
      leaf_index: 3,
      checkpoint: 'checkpoint:proof-room-transparency:8',
      inclusion_path: [
        'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      ],
      verified_at: 1766000100,
    })
    const cryptoContextReportJson = JSON.stringify({
      schema: 'chio.disclosure.crypto-context-report.v1',
      id: 'disclosure-crypto-context-report-crypto-context-buyer-auditor',
      context_id: 'crypto-context-buyer-auditor',
      artifact_ref: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      verdict: 'verified',
      evidence_class: 'verifier_context',
      cryptographic_proof_verified: true,
      verified_claims: [
        'claim.disclosure.crypto_context_bound',
        'claim.disclosure.profile_context_policy_enforced',
      ],
      rejected_checks: [],
      disclosed_fields: ['capability_id', 'id', 'tool_name'],
    })
    const verificationContextDigest = await sha256Hex(verificationContextJson)
    const keyStateDigest = await sha256Hex(keyStateJson)
    const revocationSnapshotDigest = await sha256Hex(revocationSnapshotJson)
    const privacyProfileDigest = await sha256Hex(privacyProfileJson)
    const transparencyProofDigest = await sha256Hex(transparencyProofJson)
    const cryptoContextReportDigest = await sha256Hex(cryptoContextReportJson)
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-crypto-context-valid',
        fixture_id: 'crypto-context-valid-bbs-context',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'crypto-context-verifier-digest',
          schema: 'chio.disclosure.crypto-context-report.v1',
        },
        artifacts: [
          {
            path: 'verification-context.json',
            sha256: verificationContextDigest,
            schema: 'chio.crypto.verification-context.v1',
            renderer_hint: 'crypto-verification-context',
            participates_in_primary_verdict: true,
          },
          {
            path: 'key-state.json',
            sha256: keyStateDigest,
            schema: 'chio.trust.key-state.v1',
            renderer_hint: 'trust-key-state',
            participates_in_primary_verdict: true,
          },
          {
            path: 'revocation-snapshot.json',
            sha256: revocationSnapshotDigest,
            schema: 'chio.trust.revocation-snapshot.v1',
            renderer_hint: 'trust-revocation-snapshot',
            participates_in_primary_verdict: true,
          },
          {
            path: 'verifier-privacy-profile.json',
            sha256: privacyProfileDigest,
            schema: 'chio.disclosure.verifier-privacy-profile.v1',
            renderer_hint: 'disclosure-verifier-privacy-profile',
            participates_in_primary_verdict: true,
          },
          {
            path: 'transparency-inclusion-proof.json',
            sha256: transparencyProofDigest,
            schema: 'chio.transparency.inclusion-proof.v1',
            renderer_hint: 'transparency-inclusion-proof',
            participates_in_primary_verdict: true,
          },
          {
            path: 'crypto-context-report.json',
            sha256: cryptoContextReportDigest,
            schema: 'chio.disclosure.crypto-context-report.v1',
            renderer_hint: 'disclosure-crypto-context-report',
            participates_in_primary_verdict: true,
          },
        ],
        claims: [
          {
            claim_id: 'claim.disclosure.crypto_context_bound',
            required_artifacts: [
              'verification-context.json',
              'key-state.json',
              'revocation-snapshot.json',
              'transparency-inclusion-proof.json',
              'crypto-context-report.json',
            ],
            result: 'verified',
          },
          {
            claim_id: 'claim.disclosure.profile_context_policy_enforced',
            required_artifacts: ['verifier-privacy-profile.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-crypto-context-valid',
        fixture_id: 'crypto-context-valid-bbs-context',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'crypto-context-verifier-digest',
          schema: 'chio.disclosure.crypto-context-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.disclosure.crypto_context_bound',
            source: 'crypto-context-report.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.disclosure.profile_context_policy_enforced',
            source: 'verifier-privacy-profile.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse(JSON.parse(cryptoContextReportJson)),
      '/verification-context.json': { ok: true, text: async () => verificationContextJson },
      '/key-state.json': { ok: true, text: async () => keyStateJson },
      '/revocation-snapshot.json': { ok: true, text: async () => revocationSnapshotJson },
      '/verifier-privacy-profile.json': { ok: true, text: async () => privacyProfileJson },
      '/transparency-inclusion-proof.json': { ok: true, text: async () => transparencyProofJson },
      '/crypto-context-report.json': { ok: true, text: async () => cryptoContextReportJson },
      '/proof-room-fixture-catalog.json': jsonResponse(
        {},
        { ok: false, status: 404, statusText: 'Not Found' },
      ),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Crypto Context')

    expect(fetchMock).toHaveBeenCalledWith('/verification-context.json')
    expect(fetchMock).toHaveBeenCalledWith('/key-state.json')
    expect(fetchMock).toHaveBeenCalledWith('/revocation-snapshot.json')
    expect(fetchMock).toHaveBeenCalledWith('/verifier-privacy-profile.json')
    expect(fetchMock).toHaveBeenCalledWith('/transparency-inclusion-proof.json')
    expect(fetchMock).toHaveBeenCalledWith('/crypto-context-report.json')
    expect(container.textContent).toContain('crypto-context-buyer-auditor')
    expect(container.textContent).toContain('bbs')
    expect(container.textContent).toContain('https://auditor.example/chio')
    expect(container.textContent).toContain('nonce fresh')
    expect(container.textContent).toContain('holder:buyer-agent')
    expect(container.textContent).toContain('bbs-bls12381-sha256')
    expect(container.textContent).toContain('revocation-snapshot-buyer-auditor')
    expect(container.textContent).toContain('profile-buyer-auditor-context')
    expect(container.textContent).toContain('no_replay')
    expect(container.textContent).toContain('transparency-proof-buyer-auditor')
    expect(container.textContent).toContain('checkpoint:proof-room-transparency:8')
    expect(container.textContent).toContain('verifier_context')
    expect(container.textContent).toContain('claim.disclosure.crypto_context_bound')
    expect(container.textContent).toContain('capability_id')
  })

  it('renders manifest-bound swarm authority evidence from Proof Room artifacts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const taskGraphJson = JSON.stringify({
      schema: 'chio.swarm.task-graph.v1',
      graphId: 'swarm-graph-proof-valid',
      rootTransactionRef: 'passport-swarm-valid',
      plannerSubject: 'did:chio:planner',
      maxDepth: 2,
      maxFanout: 2,
      nodes: [
        {
          taskId: 'task-root',
          depth: 0,
        },
        {
          taskId: 'task-child-a',
          parentTaskId: 'task-root',
          routePlanRef: 'route-child-a',
          continuationTokenRef: 'continuation-child-a',
          budgetAllocationRef: 'budget-child-a',
          depth: 1,
        },
        {
          taskId: 'task-child-b',
          parentTaskId: 'task-root',
          routePlanRef: 'route-child-b',
          continuationTokenRef: 'continuation-child-b',
          budgetAllocationRef: 'budget-child-b',
          depth: 1,
        },
      ],
      joins: [
        {
          joinId: 'join-child-results',
          parentTaskIds: ['task-child-a', 'task-child-b'],
          nextTaskId: 'task-root',
        },
      ],
      budgetPoolRef: 'budget-pool-swarm-valid',
      revocationEpochRef: 'revocation-epoch-swarm-valid',
    })
    const continuationJson = JSON.stringify({
      schema: 'chio.swarm.continuation-token.v1',
      tokenId: 'continuation-child-a',
      graphId: 'swarm-graph-proof-valid',
      childTaskId: 'task-child-a',
      parentTaskId: 'task-root',
      parentReceiptIds: ['receipt-root'],
      routePlanReceiptId: 'route-child-a',
      budgetAllocationId: 'budget-child-a',
      revocationEpochRef: 'revocation-epoch-swarm-valid',
      mode: 'single_use',
    })
    const witnessJson = JSON.stringify({
      schema: 'chio.swarm.delegation-witness-chain.v1',
      chainId: 'witness-child-a',
      graphId: 'swarm-graph-proof-valid',
      parentTaskId: 'task-root',
      childTaskId: 'task-child-a',
      hops: [
        {
          attenuationRuleId: 'rule-subset-tool-invocation',
          policyDigest: 'd8495bc1178cab584c79c27872d5c51b7f11d0b9a53c06028943432bdd478011',
          witnessSignature: 'sig-witness-child-a',
        },
      ],
    })
    const routeJson = JSON.stringify({
      schema: 'chio.swarm.route-plan-receipt.v1',
      routePlanId: 'route-child-a',
      graphId: 'swarm-graph-proof-valid',
      taskId: 'task-child-a',
      selectedRoute: 'mcp:task-child-a',
      bridgeId: 'mcp',
      protocolTarget: 'mcp://provider-a',
      egressConstraints: ['deny-private-network'],
      attenuationDecision: 'accepted',
    })
    const joinJson = JSON.stringify({
      schema: 'chio.swarm.join-receipt.v1',
      joinId: 'join-child-results',
      graphId: 'swarm-graph-proof-valid',
      expectedParentReceiptIds: ['receipt-child-a', 'receipt-child-b'],
      actualParentReceiptIds: ['receipt-child-a', 'receipt-child-b'],
      joinPredicate: 'all_success',
      nextTaskId: 'task-root',
    })
    const budgetJson = JSON.stringify({
      schema: 'chio.swarm.budget-pool.v1',
      poolId: 'budget-pool-swarm-valid',
      graphId: 'swarm-graph-proof-valid',
      currency: 'USD',
      totalUnits: 10000,
      allocations: [
        {
          allocationId: 'budget-child-a',
          taskId: 'task-child-a',
          maxUnits: 2500,
        },
      ],
    })
    const revocationJson = JSON.stringify({
      schema: 'chio.swarm.revocation-epoch.v1',
      epochId: 'revocation-epoch-swarm-valid',
      rootHash: 'd078a6de838c0d864b579ac35b8de638714961fce5b40cc4e5cd47c9ee41e758',
      revokedSubjects: [],
      revokedTaskIds: [],
    })
    const taskGraphDigest = await sha256Hex(taskGraphJson)
    const continuationDigest = await sha256Hex(continuationJson)
    const witnessDigest = await sha256Hex(witnessJson)
    const routeDigest = await sha256Hex(routeJson)
    const joinDigest = await sha256Hex(joinJson)
    const budgetDigest = await sha256Hex(budgetJson)
    const revocationDigest = await sha256Hex(revocationJson)
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-recursive-runtime-swarm',
        fixture_id: 'recursive-runtime-swarm',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'swarm-verifier-digest',
          schema: 'chio.swarm.authority-verifier-report.v1',
        },
        artifacts: [
          {
            path: 'task-graph.json',
            sha256: taskGraphDigest,
            schema: 'chio.swarm.task-graph.v1',
            renderer_hint: 'swarm-task-graph',
            participates_in_primary_verdict: true,
          },
          {
            path: 'continuation-child-a.json',
            sha256: continuationDigest,
            schema: 'chio.swarm.continuation-token.v1',
            renderer_hint: 'swarm-continuation-token',
            participates_in_primary_verdict: true,
          },
          {
            path: 'witness-child-a.json',
            sha256: witnessDigest,
            schema: 'chio.swarm.delegation-witness-chain.v1',
            renderer_hint: 'swarm-delegation-witness-chain',
            participates_in_primary_verdict: true,
          },
          {
            path: 'route-child-a.json',
            sha256: routeDigest,
            schema: 'chio.swarm.route-plan-receipt.v1',
            renderer_hint: 'swarm-route-plan-receipt',
            participates_in_primary_verdict: true,
          },
          {
            path: 'join-receipt.json',
            sha256: joinDigest,
            schema: 'chio.swarm.join-receipt.v1',
            renderer_hint: 'swarm-join-receipt',
            participates_in_primary_verdict: true,
          },
          {
            path: 'budget-pool.json',
            sha256: budgetDigest,
            schema: 'chio.swarm.budget-pool.v1',
            renderer_hint: 'swarm-budget-pool',
            participates_in_primary_verdict: true,
          },
          {
            path: 'revocation-epoch.json',
            sha256: revocationDigest,
            schema: 'chio.swarm.revocation-epoch.v1',
            renderer_hint: 'swarm-revocation-epoch',
            participates_in_primary_verdict: true,
          },
        ],
        claims: [
          {
            claim_id: 'claim.swarm.task_graph_bound',
            required_artifacts: ['task-graph.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.swarm.continuation_fresh',
            required_artifacts: ['continuation-child-a.json', 'revocation-epoch.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.swarm.attenuation_witness_chain_bound',
            required_artifacts: ['witness-child-a.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.swarm.route_plan_bound',
            required_artifacts: ['route-child-a.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.swarm.join_receipt_bound',
            required_artifacts: ['join-receipt.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.swarm.budget_pool_bound',
            required_artifacts: ['budget-pool.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.swarm.revocation_epoch_bound',
            required_artifacts: ['revocation-epoch.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-recursive-runtime-swarm',
        fixture_id: 'recursive-runtime-swarm',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'swarm-verifier-digest',
          schema: 'chio.swarm.authority-verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.swarm.task_graph_bound',
            source: 'task-graph.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.swarm.continuation_fresh',
            source: 'continuation-child-a.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.swarm.attenuation_witness_chain_bound',
            source: 'witness-child-a.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.swarm.route_plan_bound',
            source: 'route-child-a.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.swarm.join_receipt_bound',
            source: 'join-receipt.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.swarm.budget_pool_bound',
            source: 'budget-pool.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.swarm.revocation_epoch_bound',
            source: 'revocation-epoch.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.swarm.authority-verifier-report.v1',
        id: 'swarm-authority-verifier-report-swarm-graph-proof-valid',
        verdict: 'verified',
        verified_claims: [
          'claim.swarm.task_graph_bound',
          'claim.swarm.continuation_fresh',
          'claim.swarm.attenuation_witness_chain_bound',
          'claim.swarm.route_plan_bound',
          'claim.swarm.join_receipt_bound',
          'claim.swarm.budget_pool_bound',
          'claim.swarm.revocation_epoch_bound',
        ],
      }),
      '/task-graph.json': { ok: true, text: async () => taskGraphJson },
      '/continuation-child-a.json': { ok: true, text: async () => continuationJson },
      '/witness-child-a.json': { ok: true, text: async () => witnessJson },
      '/route-child-a.json': { ok: true, text: async () => routeJson },
      '/join-receipt.json': { ok: true, text: async () => joinJson },
      '/budget-pool.json': { ok: true, text: async () => budgetJson },
      '/revocation-epoch.json': { ok: true, text: async () => revocationJson },
      '/proof-room-fixture-catalog.json': jsonResponse(
        {},
        { ok: false, status: 404, statusText: 'Not Found' },
      ),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Swarm Authority')

    expect(fetchMock).toHaveBeenCalledWith('/task-graph.json')
    expect(fetchMock).toHaveBeenCalledWith('/continuation-child-a.json')
    expect(fetchMock).toHaveBeenCalledWith('/witness-child-a.json')
    expect(fetchMock).toHaveBeenCalledWith('/route-child-a.json')
    expect(fetchMock).toHaveBeenCalledWith('/join-receipt.json')
    expect(fetchMock).toHaveBeenCalledWith('/budget-pool.json')
    expect(fetchMock).toHaveBeenCalledWith('/revocation-epoch.json')
    expect(container.textContent).toContain('swarm-graph-proof-valid')
    expect(container.textContent).toContain('task-child-a')
    expect(container.textContent).toContain('continuation-child-a')
    expect(container.textContent).toContain('rule-subset-tool-invocation')
    expect(container.textContent).toContain('mcp://provider-a')
    expect(container.textContent).toContain('join-child-results')
    expect(container.textContent).toContain('budget-pool-swarm-valid')
    expect(container.textContent).toContain('2500 USD')
    expect(container.textContent).toContain('revocation-epoch-swarm-valid')
  })

  it('renders manifest-bound workflow preflight planning evidence from Proof Room artifacts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const preflightPlanJson = JSON.stringify({
      schema: 'chio.workflow.preflight-plan.v1',
      id: 'workflow-preflight-valid-child-scope',
      issued_at: '2026-06-10T00:00:00Z',
      parent_task: {
        task_id: 'task-parent-commerce',
        scope: {
          actions: ['inventory.read', 'quote.create'],
          resources: ['catalog:us', 'quote:cart-001'],
          route_refs: ['route-local-market'],
          approval_refs: ['approval-commerce-owner'],
          required_schemas: ['chio.commerce.order-context.v1'],
          budget_minor: 5000,
          currency: 'USD',
        },
      },
      child_tasks: [
        {
          task_id: 'task-child-quote',
          parent_task_id: 'task-parent-commerce',
          requested_scope: {
            actions: ['inventory.read', 'quote.create'],
            resources: ['catalog:us', 'quote:cart-001'],
            route_refs: ['route-local-market'],
            approval_refs: ['approval-commerce-owner'],
            required_schemas: ['chio.commerce.order-context.v1'],
            budget_minor: 3000,
            currency: 'USD',
          },
        },
      ],
      route_plans: [
        {
          route_ref: 'route-local-market',
          supported: true,
        },
      ],
      approvals: [
        {
          approval_ref: 'approval-commerce-owner',
          status: 'approved',
        },
      ],
      registry_support: {
        supported_schemas: [
          'chio.commerce.order-context.v1',
          'chio.workflow.preflight-plan.v1',
          'chio.workflow.preflight-report.v1',
        ],
      },
      budget_pool: {
        currency: 'USD',
        total_minor: 5000,
      },
      revocation: {
        epoch_id: 'revocation-epoch-001',
        root_sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        status: 'fresh',
      },
      planning_artifacts: [
        {
          artifact_ref: 'simulation-dry-run-001',
          artifact_class: 'simulation',
          satisfies_claims: [],
        },
      ],
    })
    const preflightPlanDigest = await sha256Hex(preflightPlanJson)
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-workflow-preflight-valid',
        fixture_id: 'workflow-preflight-valid',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'workflow-preflight-report-digest',
          schema: 'chio.workflow.preflight-report.v1',
        },
        artifacts: [
          {
            path: 'preflight-plan.json',
            sha256: preflightPlanDigest,
            schema: 'chio.workflow.preflight-plan.v1',
            renderer_hint: 'workflow-preflight-plan',
            participates_in_primary_verdict: true,
          },
        ],
        claims: [
          {
            claim_id: 'claim.workflow.preflight_child_scope_bounded',
            required_artifacts: ['preflight-plan.json', 'verifier/report.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'accepted',
        bundle_id: 'proof-room-workflow-preflight-valid',
        fixture_id: 'workflow-preflight-valid',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'workflow-preflight-report-digest',
          schema: 'chio.workflow.preflight-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.workflow.preflight_child_scope_bounded',
            source: 'preflight-plan.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.workflow.preflight-report.v1',
        id: 'workflow-preflight-report-workflow-preflight-valid-child-scope',
        issued_at: '2026-06-10T00:00:00Z',
        plan_id: 'workflow-preflight-valid-child-scope',
        verdict: 'accepted',
        evidence_class: 'planning',
        verified_claims: ['claim.workflow.preflight_child_scope_bounded'],
        rejected_checks: [],
        live_authority_claims: [],
      }),
      '/preflight-plan.json': { ok: true, text: async () => preflightPlanJson },
      '/proof-room-fixture-catalog.json': jsonResponse(
        {},
        { ok: false, status: 404, statusText: 'Not Found' },
      ),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Workflow Preflight')

    expect(fetchMock).toHaveBeenCalledWith('/preflight-plan.json')
    expect(container.textContent).toContain('Planning Evidence')
    expect(container.textContent).toContain('workflow-preflight-valid-child-scope')
    expect(container.textContent).toContain('task-parent-commerce')
    expect(container.textContent).toContain('task-child-quote')
    expect(container.textContent).toContain('route-local-market supported')
    expect(container.textContent).toContain('approval-commerce-owner approved')
    expect(container.textContent).toContain('simulation-dry-run-001')
    expect(container.textContent).toContain('claim.workflow.preflight_child_scope_bounded')
    expect(container.textContent).toContain('live authority claims none')
  })

  it('renders manifest-bound Agent Web projection evidence without treating external authority as Chio authority', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const agentWebEnvelopeJson = JSON.stringify({
      schema: 'chio.agent-web-proof-envelope.v1',
      envelope_id: 'agent-web-envelope-standard-webhooks-valid',
      transaction_passport_ref: 'passport-agent-web-valid',
      source_protocol: 'standard-webhooks',
      source_protocol_version: '2026-06-09',
      external_subject: 'webhook-delivery-agent-web-valid',
      external_subject_path: 'external/webhook-delivery.json',
      external_subject_digest: '0cee872f0435ed63db5f54256fdbeef885effba8dd43e5f82bb0ab870e2f8c71',
      external_subject_signature_ref: 'v1,5L5d/oR9uJZiOH43WGkTL7Q5Leb+QXd6x9VeYHmLzS4=',
      projection_manifest_ref: 'projection-standard-webhooks-valid',
      chio_claim_refs: [
        'claim.agent_web.external_subject_digest_bound',
        'claim.agent_web.projection_manifest_bound',
        'claim.agent_web.unsupported_claims_limited',
        'claim.agent_web.sidecar_not_native_authority',
      ],
      receipt_refs: ['receipt-agent-web-webhook-allow'],
      limitations: ['Webhook signature evidence is not Chio capability authority.'],
    })
    const agentWebManifestJson = JSON.stringify({
      schema: 'chio.agent-web.external-projection-manifest.v1',
      projection_id: 'projection-standard-webhooks-valid',
      source_protocol: 'standard-webhooks',
      source_version: '2026-06-09',
      digest_algorithm: 'sha256',
      signature_algorithm: 'standard-webhooks',
      requires_external_signature: true,
      unsupported_claims: ['claim.external.webhook_signature_is_chio_authority'],
      copy_limitations: [
        'Standard Webhooks signatures are external evidence and do not authorize Chio tool execution.',
      ],
    })
    const agentWebEnvelopeDigest = await sha256Hex(agentWebEnvelopeJson)
    const agentWebManifestDigest = await sha256Hex(agentWebManifestJson)
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-agent-web-interop',
        fixture_id: 'agent-web-interop',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'agent-web-verifier-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        artifacts: [
          {
            path: 'standard-webhooks-envelope.json',
            sha256: agentWebEnvelopeDigest,
            schema: 'chio.agent-web-proof-envelope.v1',
            renderer_hint: 'agent-web-proof-envelope',
            participates_in_primary_verdict: true,
          },
          {
            path: 'standard-webhooks-manifest.json',
            sha256: agentWebManifestDigest,
            schema: 'chio.agent-web.external-projection-manifest.v1',
            renderer_hint: 'agent-web-projection-manifest',
            participates_in_primary_verdict: true,
          },
        ],
        claims: [
          {
            claim_id: 'claim.agent_web.external_subject_digest_bound',
            required_artifacts: ['standard-webhooks-envelope.json'],
            result: 'verified',
          },
          {
            claim_id: 'claim.agent_web.unsupported_claims_limited',
            required_artifacts: ['standard-webhooks-manifest.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-agent-web-interop',
        fixture_id: 'agent-web-interop',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'agent-web-verifier-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.agent_web.external_subject_digest_bound',
            source: 'standard-webhooks-envelope.json',
            verdict: 'verified',
          },
          {
            claim_id: 'claim.agent_web.unsupported_claims_limited',
            source: 'standard-webhooks-manifest.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.transaction.verifier-report.v1',
        id: 'verifier-report-agent-web-interop',
        verdict: 'verified',
        verified_claims: [
          'claim.agent_web.external_subject_digest_bound',
          'claim.agent_web.unsupported_claims_limited',
        ],
      }),
      '/standard-webhooks-envelope.json': {
        ok: true,
        text: async () => agentWebEnvelopeJson,
        json: async () => JSON.parse(agentWebEnvelopeJson),
      },
      '/standard-webhooks-manifest.json': {
        ok: true,
        text: async () => agentWebManifestJson,
        json: async () => JSON.parse(agentWebManifestJson),
      },
      '/proof-room-fixture-catalog.json': jsonResponse(
        {},
        { ok: false, status: 404, statusText: 'Not Found' },
      ),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'agent-web-envelope-standard-webhooks-valid')

    expect(fetchMock).toHaveBeenCalledWith('/standard-webhooks-envelope.json')
    expect(fetchMock).toHaveBeenCalledWith('/standard-webhooks-manifest.json')
    expect(container.textContent).toContain('Agent Web')
    expect(container.textContent).toContain('standard-webhooks')
    expect(container.textContent).toContain('webhook-delivery-agent-web-valid')
    expect(container.textContent).toContain('external/webhook-delivery.json')
    expect(container.textContent).toContain('receipt-agent-web-webhook-allow')
    expect(container.textContent).toContain('claim.external.webhook_signature_is_chio_authority')
    expect(container.textContent).toContain('Webhook signature evidence is not Chio capability authority.')
    expect(container.textContent).toContain(
      'Standard Webhooks signatures are external evidence and do not authorize Chio tool execution.',
    )
  })

  it('rejects served Agent Web projection manifests with unsupported schema', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const agentWebEnvelopeJson = JSON.stringify({
      schema: 'chio.agent-web-proof-envelope.v1',
      envelope_id: 'agent-web-envelope-mcp-invalid-projection',
      transaction_passport_ref: 'passport-agent-web-valid',
      source_protocol: 'mcp',
      source_protocol_version: '2025-06-18',
      external_subject: 'mcp-tool-call',
      external_subject_path: 'external/mcp-tool-call.json',
      external_subject_digest: 'd91d74b44948a99bde89aac37a2caf720c88026c337a2f5e3be2a759a5d2c117',
      projection_manifest_ref: 'projection-mcp-invalid',
      chio_claim_refs: ['claim.agent_web.external_subject_digest_bound'],
      receipt_refs: ['receipt-agent-web-mcp-allow'],
      limitations: ['MCP tool calls are external evidence, not Chio capability authority.'],
    })
    const agentWebManifestJson = JSON.stringify({
      schema: 'chio.agent-web.unregistered-projection-manifest.v1',
      projection_id: 'projection-mcp-invalid',
      source_protocol: 'mcp',
      source_version: '2025-06-18',
      unsupported_claims: ['claim.external.mcp_tool_call_is_chio_authority'],
    })
    const agentWebEnvelopeDigest = await sha256Hex(agentWebEnvelopeJson)
    const agentWebManifestDigest = await sha256Hex(agentWebManifestJson)
    mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-agent-web-schema-boundary',
        fixture_id: 'agent-web-schema-boundary',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'agent-web-verifier-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        artifacts: [
          {
            path: 'mcp-envelope.json',
            sha256: agentWebEnvelopeDigest,
            schema: 'chio.agent-web-proof-envelope.v1',
            renderer_hint: 'agent-web-proof-envelope',
            participates_in_primary_verdict: true,
          },
          {
            path: 'mcp-manifest.json',
            sha256: agentWebManifestDigest,
            schema: 'chio.agent-web.external-projection-manifest.v1',
            renderer_hint: 'agent-web-projection-manifest',
            participates_in_primary_verdict: true,
          },
        ],
        claims: [
          {
            claim_id: 'claim.agent_web.external_subject_digest_bound',
            required_artifacts: ['mcp-envelope.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-agent-web-schema-boundary',
        fixture_id: 'agent-web-schema-boundary',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'agent-web-verifier-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.agent_web.external_subject_digest_bound',
            source: 'mcp-envelope.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.transaction.verifier-report.v1',
        id: 'verifier-report-agent-web-schema-boundary',
        verdict: 'verified',
        verified_claims: ['claim.agent_web.external_subject_digest_bound'],
      }),
      '/mcp-envelope.json': textResponse(agentWebEnvelopeJson),
      '/mcp-manifest.json': textResponse(agentWebManifestJson),
      '/proof-room-fixture-catalog.json': jsonResponse(null, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Proof Room load failed')

    expect(container.textContent).toContain('served Agent Web projection manifest has unsupported schema')
    expect(container.textContent).not.toContain('agent-web-envelope-mcp-invalid-projection')
  })

  it('renders served Proof Room data from the manifest report reference', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'custom-proof-room',
        fixture_id: 'custom-report-path',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'custom-verifier-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        proof_room_verifier_report_ref: {
          path: 'ui/custom-proof-room/load-report.json',
          sha256: 'custom-load-report-digest',
          schema: 'chio.proof-room.verifier-report.v1',
        },
        claims: [
          {
            claim_id: 'claim.proof_room.custom_report_path',
            required_artifacts: ['verifier/report.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/custom-proof-room/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'custom-proof-room',
        fixture_id: 'custom-report-path',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'custom-verifier-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.proof_room.custom_report_path',
            source: 'verifier/report.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.transaction.verifier-report.v1',
        id: 'custom-verifier-report',
        verdict: 'verified',
        verified_claims: ['claim.proof_room.custom_report_path'],
      }),
      '/proof-room-fixture-catalog.json': jsonResponse(null, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'custom-verifier-report')

    expect(fetchMock).toHaveBeenCalledWith('/ui/custom-proof-room/load-report.json')
    expect(container.textContent).toContain('claim.proof_room.custom_report_path')
    expect(container.textContent).toContain('custom-proof-room')
  })

  it('rejects served Proof Room manifest paths that escape the bundle root', async () => {
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-unsafe-path',
        fixture_id: 'unsafe-path',
        verifier_report_ref: {
          path: '/artifacts/internal/debug-notes.json',
          sha256: 'unsafe-report-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        claims: [],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-unsafe-path',
        fixture_id: 'unsafe-path',
        source_verifier_report_ref: {
          path: '/artifacts/internal/debug-notes.json',
          sha256: 'unsafe-report-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [],
      }),
      '/artifacts/internal/debug-notes.json': () =>
        Promise.reject(new Error('unsafe absolute path was fetched')),
    })

    await expect(fetchProofRoomStaticBundle()).rejects.toThrow(
      'served verifier report path is unsafe',
    )
    expect(fetchMock).not.toHaveBeenCalledWith('/artifacts/internal/debug-notes.json')
  })

  it('rejects encoded parent components in served Proof Room manifest paths', async () => {
    const fetchMock = mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-encoded-unsafe-path',
        fixture_id: 'encoded-unsafe-path',
        verifier_report_ref: {
          path: 'artifacts/%2e%2e/internal/debug-notes.json',
          sha256: 'unsafe-report-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        claims: [],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-encoded-unsafe-path',
        fixture_id: 'encoded-unsafe-path',
        source_verifier_report_ref: {
          path: 'artifacts/%2e%2e/internal/debug-notes.json',
          sha256: 'unsafe-report-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [],
      }),
      '/artifacts/%2e%2e/internal/debug-notes.json': () =>
        Promise.reject(new Error('unsafe encoded traversal was fetched')),
    })

    await expect(fetchProofRoomStaticBundle()).rejects.toThrow(
      'served verifier report path is unsafe',
    )
    expect(fetchMock).not.toHaveBeenCalledWith('/artifacts/%2e%2e/internal/debug-notes.json')
  })

  it('rejects encoded parent components in catalog verifier report paths', async () => {
    const fetchMock = mockFetch({
      '/proof-room-fixtures/%2e%2e/internal/report.json': () =>
        Promise.reject(new Error('unsafe catalog path was fetched')),
    })

    await expect(
      fetchProofRoomFixtureVerifierReport('/proof-room-fixtures/%2e%2e/internal/report.json'),
    ).rejects.toThrow(
      'unsafe Proof Room fixture verifier report path: /proof-room-fixtures/%2e%2e/internal/report.json',
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('renders failed Proof Room claim paths from the verifier report', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-single-call-authority',
        fixture_id: 'single-call-authority',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: '92368d844cd82f5504234516c0072755be99080f073258ad4ce96a5c5fe16877',
          schema: 'chio.transaction.verifier-report.v1',
        },
        claims: [
          {
            claim_id: 'claim.transaction.passport_root_verified',
            required_artifacts: ['verifier/report.json'],
            result: 'failed',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'failed',
        bundle_id: 'proof-room-single-call-authority',
        fixture_id: 'single-call-authority',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: '92368d844cd82f5504234516c0072755be99080f073258ad4ce96a5c5fe16877',
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.transaction.passport_root_verified',
            source: 'verifier/report.json',
            verdict: 'failed',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.transaction.verifier-report.v1',
        id: 'verifier-report-passport-minimal-valid',
        verdict: 'failed',
        failure_code: 'proof verify: verifier policy digest mismatch',
        error:
          'proof verify: verifier policy digest mismatch: expected policy-a, got policy-b',
        passport_id: 'passport-minimal-valid',
        passport_path: 'transaction-passport.json',
        evidence_graph_path: 'evidence-graph.json',
        verifier_policy_path: 'verifier-policy.json',
        verified_claims: [],
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Primary verdict failed')

    expect(container.textContent).toContain('claim.transaction.passport_root_verified')
    expect(container.textContent).toContain('Failed')
    expect(container.textContent).toContain('proof verify: verifier policy digest mismatch')
    expect(container.textContent).toContain('expected policy-a, got policy-b')
    expect(container.textContent).toContain('verifier/report.json')
  })

  it('rejects served Proof Room data when the verifier report digest does not match the manifest', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'tampered-verifier-report',
      verdict: 'verified',
      passport_id: 'tampered-passport',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const actualVerifierDigest = await sha256Hex(verifierReportJson)
    const manifestVerifierDigest = `0${actualVerifierDigest.slice(1)}`
    mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-digest-boundary',
        fixture_id: 'digest-boundary',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: manifestVerifierDigest,
          schema: 'chio.transaction.verifier-report.v1',
        },
        claims: [
          {
            claim_id: 'claim.transaction.passport_root_verified',
            required_artifacts: ['verifier/report.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-digest-boundary',
        fixture_id: 'digest-boundary',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: manifestVerifierDigest,
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.transaction.passport_root_verified',
            source: 'verifier/report.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': textResponse(verifierReportJson),
      '/proof-room-fixture-catalog.json': jsonResponse({}, { ok: false, status: 404, statusText: 'Not Found' }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Proof Room load failed')

    expect(container.textContent).toContain('served verifier report digest does not match the manifest')
    expect(container.textContent).not.toContain('tampered-verifier-report')
  })

  it('rejects served Proof Room data when the load report digest does not match the manifest', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'digest-bound-verifier-report',
      verdict: 'verified',
      passport_id: 'digest-bound-passport',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'proof-room-load-report-boundary',
      fixture_id: 'load-report-boundary',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          source: 'verifier/report.json',
          verdict: 'verified',
        },
      ],
    })
    const actualLoadReportDigest = await sha256Hex(loadReportJson)
    const manifestLoadReportDigest = `0${actualLoadReportDigest.slice(1)}`
    mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-load-report-boundary',
        fixture_id: 'load-report-boundary',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: verifierReportDigest,
          schema: 'chio.transaction.verifier-report.v1',
        },
        proof_room_verifier_report_ref: {
          path: 'ui/proof-room-static/load-report.json',
          sha256: manifestLoadReportDigest,
          schema: 'chio.proof-room.verifier-report.v1',
        },
        claims: [
          {
            claim_id: 'claim.transaction.passport_root_verified',
            required_artifacts: ['verifier/report.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': textResponse(loadReportJson),
      '/verifier/report.json': textResponse(verifierReportJson),
      '/proof-room-fixture-catalog.json': jsonResponse(null, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Proof Room load failed')

    expect(container.textContent).toContain('served load report digest does not match the manifest')
    expect(container.textContent).not.toContain('digest-bound-verifier-report')
  })

  it('rejects served Proof Room data when the load report verifies a claim absent from the verifier report', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'proof-room-verifier-claim-boundary',
        fixture_id: 'verifier-claim-boundary',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: '92368d844cd82f5504234516c0072755be99080f073258ad4ce96a5c5fe16877',
          schema: 'chio.transaction.verifier-report.v1',
        },
        claims: [
          {
            claim_id: 'claim.proof_room.unbacked_claim',
            required_artifacts: ['verifier/report.json'],
            result: 'verified',
          },
        ],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'proof-room-verifier-claim-boundary',
        fixture_id: 'verifier-claim-boundary',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: '92368d844cd82f5504234516c0072755be99080f073258ad4ce96a5c5fe16877',
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [
          {
            claim_id: 'claim.proof_room.unbacked_claim',
            source: 'verifier/report.json',
            verdict: 'verified',
          },
        ],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.transaction.verifier-report.v1',
        id: 'verifier-report-without-claim',
        verdict: 'verified',
        passport_id: 'passport-minimal-valid',
        passport_path: 'transaction-passport.json',
        evidence_graph_path: 'evidence-graph.json',
        verifier_policy_path: 'verifier-policy.json',
        verified_claims: [],
      }),
      '/proof-room-fixture-catalog.json': jsonResponse(null, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Proof Room load failed')

    expect(container.textContent).toContain('load report verifies a claim absent from the verifier report')
    expect(container.textContent).not.toContain('verifier-report-without-claim')
  })

  it('rejects a selected Proof Room report set without verifier root artifacts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch(servedProofRoomRoutes('served-proof-room', 'single-call-authority', 'served-report-digest', {
      passport_id: 'served-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
    }))

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-verifier-report',
      verdict: 'failed',
      passport_id: 'uploaded-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: [],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const manifest = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.bundle.v1',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'commerce-payment-wrong-merchant',
          verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: verifierReportDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          artifacts: [
            {
              path: 'payment-lifecycle.json',
              sha256: '0000000000000000000000000000000000000000000000000000000000000000',
              schema: 'external.payment-lifecycle-placeholder.v1',
              renderer_hint: 'negative-case-artifact',
            },
          ],
          claims: [
            {
              claim_id: 'claim.commerce.payment_merchant_bound',
              required_artifacts: ['payment-lifecycle.json'],
              result: 'failed',
            },
          ],
          negative_cases: [
            {
              id: 'payment-wrong-merchant',
              path: 'transaction-passport.json',
              expected_failure_code: 'payment merchant mismatch',
            },
          ],
        }),
      ],
      'manifest.json',
      { type: 'application/json' },
    )
    const loadReport = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.verifier-report.v1',
          verdict: 'failed',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'commerce-payment-wrong-merchant',
          source_verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: verifierReportDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          ui_verdict_source: 'verifier_report_ref',
          rendered_claims: [
            {
              claim_id: 'claim.commerce.payment_merchant_bound',
              source: 'verifier/report.json',
              verdict: 'failed',
            },
          ],
        }),
      ],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [manifest, loadReport, verifierReport],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'selected files must include transaction-passport.json')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room bundle when server upload verification fails', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    const fetchMock = mockFetch({
      ...servedProofRoomRoutesWithVerifierRoots(),
      '/proof-room/upload/verify': jsonResponse({
        schema: 'chio.proof-room.upload-verification.v1',
        verdict: 'failed',
        error: 'proof-room.signature.trusted-signers-missing',
      }, {
        status: 422,
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: await selectedVerifiedProofRoomFiles(),
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'proof-room.signature.trusted-signers-missing')

    expect(fetchMock).toHaveBeenCalledWith('/proof-room/upload/verify', expect.objectContaining({
      method: 'POST',
      body: expect.any(FormData),
    }))
    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room bundle when a manifest-bound verifier root digest does not match', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      '/manifest.json': jsonResponse({
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'served-proof-room',
        fixture_id: 'single-call-authority',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'served-report-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        claims: [],
        negative_cases: [],
      }),
      '/ui/proof-room-static/load-report.json': jsonResponse({
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'served-proof-room',
        fixture_id: 'single-call-authority',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: 'served-report-digest',
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [],
      }),
      '/verifier/report.json': jsonResponse({
        schema: 'chio.transaction.verifier-report.v1',
        id: 'served-verifier-report',
        verdict: 'verified',
        verified_claims: [],
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'tampered-upload',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          source: 'verifier/report.json',
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const expectedPassportJson = JSON.stringify({
      schema: 'chio.transaction-passport.v1',
      id: 'uploaded-passport',
    })
    const tamperedPassportJson = JSON.stringify({
      schema: 'chio.transaction-passport.v1',
      id: 'tampered-uploaded-passport',
    })
    const evidenceGraphJson = JSON.stringify({
      schema: 'chio.transaction.evidence-graph.v1',
      id: 'uploaded-evidence-graph',
    })
    const manifest = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.bundle.v1',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'tampered-upload',
          transaction_passport_ref: {
            path: 'roots/transaction-passport.json',
            sha256: await sha256Hex(expectedPassportJson),
            schema: 'chio.transaction-passport.v1',
          },
          evidence_graph_ref: {
            path: 'roots/evidence-graph.json',
            sha256: await sha256Hex(evidenceGraphJson),
            schema: 'chio.transaction.evidence-graph.v1',
          },
          verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: verifierReportDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          proof_room_verifier_report_ref: {
            path: 'ui/proof-room-static/load-report.json',
            sha256: loadReportDigest,
            schema: 'chio.proof-room.verifier-report.v1',
          },
          claims: [
            {
              claim_id: 'claim.transaction.passport_root_verified',
              required_artifacts: ['verifier/report.json'],
              result: 'verified',
            },
          ],
          negative_cases: [],
        }),
      ],
      'manifest.json',
      { type: 'application/json' },
    )
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const transactionPassport = new File(
      [tamperedPassportJson],
      'roots/transaction-passport.json',
      { type: 'application/json' },
    )
    const evidenceGraph = new File([evidenceGraphJson], 'roots/evidence-graph.json', {
      type: 'application/json',
    })
    const verifierPolicy = new File(['{}'], 'roots/verifier-policy.json', {
      type: 'application/json',
    })

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [manifest, loadReport, verifierReport, transactionPassport, evidenceGraph, verifierPolicy],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'selected transaction passport digest does not match the manifest')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('loads a selected Proof Room bundle from the manifest report reference', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      ...servedProofRoomRoutes('served-proof-room', 'single-call-authority'),
      '/proof-room-fixture-catalog.json': jsonResponse({}, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-custom-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-custom-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.proof_room.custom_report_path'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-custom-report-path',
      fixture_id: 'custom-report-path',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.proof_room.custom_report_path',
          source: 'verifier/report.json',
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'uploaded-custom-report-path',
      fixture_id: 'custom-report-path',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      proof_room_verifier_report_ref: {
        path: 'ui/custom-proof-room/load-report.json',
        sha256: loadReportDigest,
        schema: 'chio.proof-room.verifier-report.v1',
      },
      signature: {
        kind: 'detached-dsse',
        signature_ref: 'bundle-signature.dsse.json',
      },
      claims: [
        {
          claim_id: 'claim.proof_room.custom_report_path',
          required_artifacts: ['verifier/report.json'],
          result: 'verified',
        },
      ],
      negative_cases: [],
    })
    const manifest = uploadedJsonFile(manifestJson, 'manifest.json')
    const signature = await signedProofRoomManifestFile(manifestJson)
    const loadReport = new File(
      [loadReportJson],
      'ui/custom-proof-room/load-report.json',
      { type: 'application/json' },
    )
    const defaultLoadReport = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.verifier-report.v1',
          verdict: 'verified',
          bundle_id: 'wrong-load-report',
          fixture_id: 'custom-report-path',
          source_verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: verifierReportDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          ui_verdict_source: 'verifier_report_ref',
          rendered_claims: [],
        }),
      ],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          signature,
          defaultLoadReport,
          loadReport,
          verifierReport,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'uploaded-custom-report-path')

    expect(container.textContent).toContain('claim.proof_room.custom_report_path')
    expect(container.textContent).not.toContain('served-proof-room')
  })

  it('allows selected Proof Room bundle upload when the served bundle fails to load', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      '/manifest.json': jsonResponse(null, {
        ok: false,
        status: 503,
        statusText: 'Unavailable',
      }),
      '/proof-room-fixture-catalog.json': jsonResponse({
        schema: 'chio.proof-room.fixture-catalog.v1',
        fixtures: [],
        available_fixtures: [],
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Proof Room load failed')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing after served bundle failure')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-after-served-failure-report',
      verdict: 'verified',
      passport_id: 'uploaded-after-served-failure-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.proof_room.upload_recovery'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-after-served-failure',
      fixture_id: 'upload-recovery',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.proof_room.upload_recovery',
          source: 'verifier/report.json',
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'uploaded-after-served-failure',
      fixture_id: 'upload-recovery',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      proof_room_verifier_report_ref: {
        path: 'ui/proof-room-static/load-report.json',
        sha256: loadReportDigest,
        schema: 'chio.proof-room.verifier-report.v1',
      },
      signature: {
        kind: 'detached-dsse',
        signature_ref: 'bundle-signature.dsse.json',
      },
      claims: [
        {
          claim_id: 'claim.proof_room.upload_recovery',
          required_artifacts: ['verifier/report.json'],
          result: 'verified',
        },
      ],
      negative_cases: [],
    })
    const manifest = uploadedJsonFile(manifestJson, 'manifest.json')
    const signature = await signedProofRoomManifestFile(manifestJson)
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          signature,
          loadReport,
          verifierReport,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'uploaded-after-served-failure')

    expect(container.textContent).toContain('claim.proof_room.upload_recovery')
  })

  it('rejects selected Proof Room bundle manifest paths that escape the bundle root', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      ...servedProofRoomRoutes('served-proof-room', 'single-call-authority'),
      '/proof-room-fixture-catalog.json': jsonResponse({}, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-unsafe-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-unsafe-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.proof_room.custom_report_path'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const unsafeVerifierReportPath = '../secret/verifier/report.json'
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-unsafe-proof-room',
      fixture_id: 'unsafe-selected-path',
      source_verifier_report_ref: {
        path: unsafeVerifierReportPath,
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.proof_room.custom_report_path',
          source: unsafeVerifierReportPath,
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const manifest = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.bundle.v1',
          bundle_id: 'uploaded-unsafe-proof-room',
          fixture_id: 'unsafe-selected-path',
          verifier_report_ref: {
            path: unsafeVerifierReportPath,
            sha256: verifierReportDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          proof_room_verifier_report_ref: {
            path: 'ui/proof-room-static/load-report.json',
            sha256: loadReportDigest,
            schema: 'chio.proof-room.verifier-report.v1',
          },
          claims: [
            {
              claim_id: 'claim.proof_room.custom_report_path',
              required_artifacts: [unsafeVerifierReportPath],
              result: 'verified',
            },
          ],
          negative_cases: [],
        }),
      ],
      'manifest.json',
      { type: 'application/json' },
    )
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'report.json',
      { type: 'application/json' },
    )
    Object.defineProperty(verifierReport, 'webkitRelativePath', {
      value: `bundle/${unsafeVerifierReportPath}`,
      configurable: true,
    })
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles('')

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          loadReport,
          verifierReport,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    const matched = await waitForAnyText(container, [
      'selected verifier report path is unsafe',
      'unsafe Proof Room asset path',
      'uploaded-unsafe-proof-room',
    ])

    expect(['selected verifier report path is unsafe', 'unsafe Proof Room asset path']).toContain(matched)
    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-unsafe-proof-room')
  })

  it('rejects selected Proof Room claims backed only by unmanifested artifacts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      ...servedProofRoomRoutes('served-proof-room', 'single-call-authority'),
      '/proof-room-fixture-catalog.json': jsonResponse({}, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-unmanifested-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-unmanifested-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.proof_room.custom_report_path'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const unmanifestedArtifactPath = 'artifacts/ghost-report.json'
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-unmanifested-proof-room',
      fixture_id: 'unmanifested-claim-source',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.proof_room.custom_report_path',
          source: unmanifestedArtifactPath,
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const manifest = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.bundle.v1',
          bundle_id: 'uploaded-unmanifested-proof-room',
          fixture_id: 'unmanifested-claim-source',
          verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: verifierReportDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          proof_room_verifier_report_ref: {
            path: 'ui/proof-room-static/load-report.json',
            sha256: loadReportDigest,
            schema: 'chio.proof-room.verifier-report.v1',
          },
          claims: [
            {
              claim_id: 'claim.proof_room.custom_report_path',
              required_artifacts: [unmanifestedArtifactPath],
              result: 'verified',
            },
          ],
          negative_cases: [],
        }),
      ],
      'manifest.json',
      { type: 'application/json' },
    )
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles('')

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [manifest, loadReport, verifierReport, transactionPassport, evidenceGraph, verifierPolicy],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    const matched = await waitForAnyText(container, [
      `selected manifest claim references unmanifested artifact: ${unmanifestedArtifactPath}`,
      'uploaded-unmanifested-proof-room',
    ])

    expect(matched).toBe(
      `selected manifest claim references unmanifested artifact: ${unmanifestedArtifactPath}`,
    )
    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-unmanifested-proof-room')
  })

  it('renders selected bundle risk comptroller details from an uploaded manifest artifact', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      ...servedProofRoomRoutes('served-proof-room', 'single-call-authority'),
      '/proof-room-fixture-catalog.json': jsonResponse({}, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const riskReportJson = JSON.stringify({
      schema: 'chio.risk.comptroller-report.v1',
      id: 'uploaded-risk-comptroller',
      facility: {
        facility_id: 'uploaded-facility',
        state: 'reserve_controlled',
        reserve_currency: 'USD',
        reserve_units: 1200,
        reserve_ref: 'uploaded-reserve',
      },
      coverage: {
        coverage_id: 'uploaded-coverage',
        order_id: 'uploaded-order',
        currency: 'USD',
        exposure_units: 5000,
        status: 'bound',
      },
      reconciliation: {
        order_id: 'uploaded-order',
        currency: 'USD',
        reserve_units: 1200,
        consumed_reserve_units: 600,
        payout_units: 600,
        settlement_units: 600,
        status: 'balanced',
      },
      reserve_ledger: [
        {
          entry_id: 'uploaded-ledger-row',
          receipt_ref: 'uploaded-risk-receipt',
          lane: 'reserve_release',
          reserve_ref: 'uploaded-reserve',
          currency: 'USD',
          units: 600,
        },
      ],
    })
    const riskReportDigest = await sha256Hex(riskReportJson)
    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-risk-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-risk-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.risk.comptroller_report_bound'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-risk-proof-room',
      fixture_id: 'uploaded-risk-fixture',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.risk.comptroller_report_bound',
          source: 'risk-comptroller-report.json',
          verdict: 'verified',
        },
      ],
    })
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'uploaded-risk-proof-room',
      fixture_id: 'uploaded-risk-fixture',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      signature: {
        kind: 'detached-dsse',
        signature_ref: 'bundle-signature.dsse.json',
      },
      artifacts: [
        {
          path: 'risk-comptroller-report.json',
          sha256: riskReportDigest,
          schema: 'chio.risk.comptroller-report.v1',
          renderer_hint: 'risk-comptroller-report',
        },
      ],
      claims: [
        {
          claim_id: 'claim.risk.comptroller_report_bound',
          required_artifacts: ['risk-comptroller-report.json'],
          result: 'verified',
        },
      ],
      negative_cases: [],
    })
    const manifest = uploadedJsonFile(manifestJson, 'manifest.json')
    const signature = await signedProofRoomManifestFile(manifestJson)
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const riskReport = new File(
      [riskReportJson],
      'risk-comptroller-report.json',
      { type: 'application/json' },
    )
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          signature,
          loadReport,
          verifierReport,
          riskReport,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'uploaded-facility')

    expect(container.textContent).toContain('uploaded-risk-proof-room')
    expect(container.textContent).toContain('uploaded-risk-receipt')
    expect(container.textContent).not.toContain('served-proof-room')
  })

  it('renders selected bundle Agent Web projection evidence from uploaded manifest artifacts', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      ...servedProofRoomRoutes('served-proof-room', 'single-call-authority'),
      '/proof-room-fixture-catalog.json': jsonResponse({}, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const agentWebEnvelopeJson = JSON.stringify({
      schema: 'chio.agent-web-proof-envelope.v1',
      envelope_id: 'uploaded-agent-web-envelope',
      source_protocol: 'mcp',
      source_protocol_version: '2025-06-18',
      external_subject: 'uploaded-mcp-tool-call',
      external_subject_path: 'external/mcp-tool-call.json',
      external_subject_digest: 'd91d74b44948a99bde89aac37a2caf720c88026c337a2f5e3be2a759a5d2c117',
      projection_manifest_ref: 'uploaded-mcp-projection',
      chio_claim_refs: ['claim.agent_web.external_subject_digest_bound'],
      receipt_refs: ['uploaded-agent-web-receipt'],
      limitations: ['MCP tool calls are external evidence, not Chio capability authority.'],
    })
    const agentWebManifestJson = JSON.stringify({
      schema: 'chio.agent-web.external-projection-manifest.v1',
      projection_id: 'uploaded-mcp-projection',
      source_protocol: 'mcp',
      source_version: '2025-06-18',
      digest_algorithm: 'sha256',
      unsupported_claims: ['claim.external.mcp_tool_call_is_chio_authority'],
      copy_limitations: ['MCP authority claims must remain unsupported unless Chio limits them.'],
    })
    const agentWebEnvelopeDigest = await sha256Hex(agentWebEnvelopeJson)
    const agentWebManifestDigest = await sha256Hex(agentWebManifestJson)
    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-agent-web-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-agent-web-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.agent_web.external_subject_digest_bound'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-agent-web-proof-room',
      fixture_id: 'uploaded-agent-web-fixture',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.agent_web.external_subject_digest_bound',
          source: 'mcp-envelope.json',
          verdict: 'verified',
        },
      ],
    })
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'uploaded-agent-web-proof-room',
      fixture_id: 'uploaded-agent-web-fixture',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      signature: {
        kind: 'detached-dsse',
        signature_ref: 'bundle-signature.dsse.json',
      },
      artifacts: [
        {
          path: 'mcp-envelope.json',
          sha256: agentWebEnvelopeDigest,
          schema: 'chio.agent-web-proof-envelope.v1',
          renderer_hint: 'agent-web-proof-envelope',
        },
        {
          path: 'mcp-manifest.json',
          sha256: agentWebManifestDigest,
          schema: 'chio.agent-web.external-projection-manifest.v1',
          renderer_hint: 'agent-web-projection-manifest',
        },
      ],
      claims: [
        {
          claim_id: 'claim.agent_web.external_subject_digest_bound',
          required_artifacts: ['mcp-envelope.json'],
          result: 'verified',
        },
      ],
      negative_cases: [],
    })
    const manifest = uploadedJsonFile(manifestJson, 'manifest.json')
    const signature = await signedProofRoomManifestFile(manifestJson)
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const agentWebEnvelope = new File(
      [agentWebEnvelopeJson],
      'mcp-envelope.json',
      { type: 'application/json' },
    )
    const agentWebManifest = new File(
      [agentWebManifestJson],
      'mcp-manifest.json',
      { type: 'application/json' },
    )
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          signature,
          loadReport,
          verifierReport,
          agentWebEnvelope,
          agentWebManifest,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'uploaded-agent-web-envelope')

    expect(container.textContent).toContain('uploaded-agent-web-proof-room')
    expect(container.textContent).toContain('uploaded-agent-web-receipt')
    expect(container.textContent).toContain('claim.external.mcp_tool_call_is_chio_authority')
    expect(container.textContent).toContain('MCP authority claims must remain unsupported unless Chio limits them.')
    expect(container.textContent).not.toContain('served-proof-room')
  })

  it('rejects a selected Proof Room load report whose bytes do not match the manifest digest', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch({
      ...servedProofRoomRoutes('served-proof-room', 'single-call-authority'),
      '/proof-room-fixture-catalog.json': jsonResponse({}, {
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    })

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-verifier-report',
      verdict: 'verified',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const manifest = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.bundle.v1',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'single-call-authority',
          verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: verifierReportDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          proof_room_verifier_report_ref: {
            path: 'ui/proof-room-static/load-report.json',
            sha256: '0'.repeat(64),
            schema: 'chio.proof-room.verifier-report.v1',
          },
          claims: [
            {
              claim_id: 'claim.transaction.passport_root_verified',
              required_artifacts: ['verifier/report.json'],
              result: 'verified',
            },
          ],
          negative_cases: [],
        }),
      ],
      'manifest.json',
      { type: 'application/json' },
    )
    const loadReport = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.verifier-report.v1',
          verdict: 'verified',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'single-call-authority',
          source_verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: verifierReportDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          ui_verdict_source: 'verifier_report_ref',
          rendered_claims: [
            {
              claim_id: 'claim.transaction.passport_root_verified',
              source: 'verifier/report.json',
              verdict: 'verified',
            },
          ],
        }),
      ],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [manifest, loadReport, verifierReport],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'load report digest does not match the manifest')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room bundle when its detached signature is missing from the manifest', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch(servedProofRoomRoutesWithVerifierRoots())

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          source: 'verifier/report.json',
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const manifest = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.bundle.v1',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'single-call-authority',
          verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: verifierReportDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          proof_room_verifier_report_ref: {
            path: 'ui/proof-room-static/load-report.json',
            sha256: loadReportDigest,
            schema: 'chio.proof-room.verifier-report.v1',
          },
          claims: [
            {
              claim_id: 'claim.transaction.passport_root_verified',
              required_artifacts: ['verifier/report.json'],
              result: 'verified',
            },
          ],
          negative_cases: [],
        }),
      ],
      'manifest.json',
      { type: 'application/json' },
    )
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          loadReport,
          verifierReport,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'selected bundle signature missing')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room bundle with an unsafe excluded artifact path', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch(servedProofRoomRoutesWithVerifierRoots())

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          source: 'verifier/report.json',
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      proof_room_verifier_report_ref: {
        path: 'ui/proof-room-static/load-report.json',
        sha256: loadReportDigest,
        schema: 'chio.proof-room.verifier-report.v1',
      },
      signature: {
        kind: 'detached-dsse',
        signature_ref: 'bundle-signature.dsse.json',
      },
      claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          required_artifacts: ['verifier/report.json'],
          result: 'verified',
        },
      ],
      negative_cases: [],
      excluded_artifacts: [
        {
          path: '../outside.json',
          reason: 'outside bundle',
        },
      ],
    })
    const manifest = uploadedJsonFile(manifestJson, 'manifest.json')
    const signature = await signedProofRoomManifestFile(manifestJson)
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          signature,
          loadReport,
          verifierReport,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'selected excluded artifact path is unsafe')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room bundle when its detached signature file is missing', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch(servedProofRoomRoutesWithVerifierRoots())

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          source: 'verifier/report.json',
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const manifest = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.bundle.v1',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'single-call-authority',
          verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: verifierReportDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          proof_room_verifier_report_ref: {
            path: 'ui/proof-room-static/load-report.json',
            sha256: loadReportDigest,
            schema: 'chio.proof-room.verifier-report.v1',
          },
          signature: {
            kind: 'detached-dsse',
            signature_ref: 'bundle-signature.dsse.json',
          },
          claims: [
            {
              claim_id: 'claim.transaction.passport_root_verified',
              required_artifacts: ['verifier/report.json'],
              result: 'verified',
            },
          ],
          negative_cases: [],
        }),
      ],
      'manifest.json',
      { type: 'application/json' },
    )
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          loadReport,
          verifierReport,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'selected files must include bundle-signature.dsse.json')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room bundle when its detached signature payload digest is wrong', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch(servedProofRoomRoutesWithVerifierRoots())

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          source: 'verifier/report.json',
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      proof_room_verifier_report_ref: {
        path: 'ui/proof-room-static/load-report.json',
        sha256: loadReportDigest,
        schema: 'chio.proof-room.verifier-report.v1',
      },
      signature: {
        kind: 'detached-dsse',
        signature_ref: 'bundle-signature.dsse.json',
      },
      claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          required_artifacts: ['verifier/report.json'],
          result: 'verified',
        },
      ],
      negative_cases: [],
    })
    const manifest = new File([manifestJson], 'manifest.json', {
      type: 'application/json',
    })
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const signature = new File(
      [
        JSON.stringify({
          payloadType: 'application/vnd.chio.proof-room.bundle.v1+json',
          payloadRef: {
            path: 'manifest.json',
            schema: 'chio.proof-room.bundle.v1',
            sha256: '0'.repeat(64),
          },
          signatures: [{ keyid: 'trusted-test-key', sig: 'trusted-test-sig' }],
        }),
      ],
      'bundle-signature.dsse.json',
      { type: 'application/json' },
    )
    mockTrustedProofRoomSignerKeys.add('1'.repeat(64))
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          loadReport,
          verifierReport,
          signature,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'signature payload digest does not match the manifest')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room bundle when its detached signature is forged', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch(servedProofRoomRoutesWithVerifierRoots())

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          source: 'verifier/report.json',
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      proof_room_verifier_report_ref: {
        path: 'ui/proof-room-static/load-report.json',
        sha256: loadReportDigest,
        schema: 'chio.proof-room.verifier-report.v1',
      },
      signature: {
        kind: 'detached-dsse',
        signature_ref: 'bundle-signature.dsse.json',
      },
      claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          required_artifacts: ['verifier/report.json'],
          result: 'verified',
        },
      ],
      negative_cases: [],
    })
    const manifestDigest = await sha256Hex(manifestJson)
    const manifest = new File([manifestJson], 'manifest.json', {
      type: 'application/json',
    })
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const signature = new File(
      [
        JSON.stringify({
          payloadType: 'application/vnd.chio.proof-room.bundle.v1+json',
          payloadRef: {
            path: 'manifest.json',
            schema: 'chio.proof-room.bundle.v1',
            sha256: manifestDigest,
          },
          signatures: [{ keyid: '1'.repeat(64), sig: '0'.repeat(128) }],
        }),
      ],
      'bundle-signature.dsse.json',
      { type: 'application/json' },
    )
    mockTrustedProofRoomSignerKeys.add('1'.repeat(64))
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          loadReport,
          verifierReport,
          signature,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'selected bundle signature verification failed')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room bundle signed outside its trust roots', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch(servedProofRoomRoutesWithVerifierRoots())

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          source: 'verifier/report.json',
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const trustedKeyId = '2'.repeat(64)
    const trustRootsJson = JSON.stringify({
      schema: 'chio.proof.first-run.trust-roots.v1',
      id: 'uploaded-trust-roots',
      trust_domain: 'did:chio:test',
      roots: [
        {
          subject: 'did:chio:trusted-test-root',
          key_id: trustedKeyId,
          key_digest: await sha256Hex(trustedKeyId),
        },
      ],
      signature: 'sig-uploaded-trust-roots',
    })
    const trustRootsDigest = await sha256Hex(trustRootsJson)
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      proof_room_verifier_report_ref: {
        path: 'ui/proof-room-static/load-report.json',
        sha256: loadReportDigest,
        schema: 'chio.proof-room.verifier-report.v1',
      },
      signature: {
        kind: 'detached-dsse',
        signature_ref: 'bundle-signature.dsse.json',
      },
      artifacts: [
        {
          path: 'artifacts/authority/trust-roots.json',
          sha256: trustRootsDigest,
          schema: 'chio.proof.first-run.trust-roots.v1',
          renderer_hint: 'trust-roots',
        },
      ],
      claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          required_artifacts: ['verifier/report.json'],
          result: 'verified',
        },
      ],
      negative_cases: [],
    })
    const manifestDigest = await sha256Hex(manifestJson)
    const keypair = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair
    const signerKeyId = bytesToHex(await crypto.subtle.exportKey('raw', keypair.publicKey))
    const signatureBytes = await crypto.subtle.sign(
      { name: 'Ed25519' },
      keypair.privateKey,
      dssePreAuthEncoding('application/vnd.chio.proof-room.bundle.v1+json', manifestJson),
    )
    const manifest = new File([manifestJson], 'manifest.json', {
      type: 'application/json',
    })
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const signature = new File(
      [
        JSON.stringify({
          payloadType: 'application/vnd.chio.proof-room.bundle.v1+json',
          payloadRef: {
            path: 'manifest.json',
            schema: 'chio.proof-room.bundle.v1',
            sha256: manifestDigest,
          },
          signatures: [{ keyid: signerKeyId, sig: bytesToHex(signatureBytes) }],
        }),
      ],
      'bundle-signature.dsse.json',
      { type: 'application/json' },
    )
    const trustRoots = new File(
      [trustRootsJson],
      'artifacts/authority/trust-roots.json',
      { type: 'application/json' },
    )
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          loadReport,
          verifierReport,
          signature,
          trustRoots,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'selected bundle signature signer is not trusted')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room bundle trusted only by uploaded trust roots', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch(servedProofRoomRoutesWithVerifierRoots())

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          source: 'verifier/report.json',
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const { keypair, signerKeyId } = await generatedProofRoomSigner()
    const trustRootsJson = JSON.stringify({
      schema: 'chio.proof.first-run.trust-roots.v1',
      id: 'uploaded-trust-roots',
      trust_domain: 'did:chio:test',
      roots: [
        {
          subject: 'did:chio:uploaded-bundle-local-signer',
          key_id: signerKeyId,
          key_digest: await sha256Hex(signerKeyId),
        },
      ],
      signature: 'sig-uploaded-trust-roots',
    })
    const trustRootsDigest = await sha256Hex(trustRootsJson)
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      proof_room_verifier_report_ref: {
        path: 'ui/proof-room-static/load-report.json',
        sha256: loadReportDigest,
        schema: 'chio.proof-room.verifier-report.v1',
      },
      signature: {
        kind: 'detached-dsse',
        signature_ref: 'bundle-signature.dsse.json',
      },
      artifacts: [
        {
          path: 'artifacts/authority/trust-roots.json',
          sha256: trustRootsDigest,
          schema: 'chio.proof.first-run.trust-roots.v1',
          renderer_hint: 'trust-roots',
        },
      ],
      claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          required_artifacts: ['verifier/report.json'],
          result: 'verified',
        },
      ],
      negative_cases: [],
    })
    const manifest = new File([manifestJson], 'manifest.json', {
      type: 'application/json',
    })
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const signature = await signedProofRoomManifestFileWithSigner(
      manifestJson,
      keypair,
      signerKeyId,
      false,
    )
    const trustRoots = new File(
      [trustRootsJson],
      'artifacts/authority/trust-roots.json',
      { type: 'application/json' },
    )
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          loadReport,
          verifierReport,
          signature,
          trustRoots,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'selected bundle signature signer is not trusted')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room bundle with mismatched negative-case evidence', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch(servedProofRoomRoutesWithVerifierRoots())

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      id: 'uploaded-verifier-report',
      verdict: 'verified',
      passport_id: 'uploaded-passport',
      passport_path: 'transaction-passport.json',
      evidence_graph_path: 'evidence-graph.json',
      verifier_policy_path: 'verifier-policy.json',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'uploaded-proof-room',
      fixture_id: 'single-call-authority',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [
        {
          claim_id: 'claim.transaction.passport_root_verified',
          source: 'verifier/report.json',
          verdict: 'verified',
        },
      ],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const manifest = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.bundle.v1',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'single-call-authority',
          verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: verifierReportDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          proof_room_verifier_report_ref: {
            path: 'ui/proof-room-static/load-report.json',
            sha256: loadReportDigest,
            schema: 'chio.proof-room.verifier-report.v1',
          },
          claims: [
            {
              claim_id: 'claim.transaction.passport_root_verified',
              required_artifacts: ['verifier/report.json'],
              result: 'verified',
            },
          ],
          negative_cases: [
            {
              id: 'policy-hash-mismatch',
              path: 'negatives/policy-hash-mismatch',
              expected_failure_code: 'verifier policy digest mismatch',
              observed_failure_code: 'proof verify: unrelated failure',
            },
          ],
        }),
      ],
      'manifest.json',
      { type: 'application/json' },
    )
    const loadReport = new File(
      [loadReportJson],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [verifierReportJson],
      'verifier/report.json',
      { type: 'application/json' },
    )
    const [transactionPassport, evidenceGraph, verifierPolicy] = selectedVerifierRootFiles()

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [
          manifest,
          loadReport,
          verifierReport,
          transactionPassport,
          evidenceGraph,
          verifierPolicy,
        ],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'negative case observed failure does not match expected failure')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room load report that is not bound to the manifest', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch(servedProofRoomRoutesWithVerifierRoots())

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const manifest = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.bundle.v1',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'single-call-authority',
          verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: 'uploaded-report-digest',
            schema: 'chio.transaction.verifier-report.v1',
          },
          claims: [],
          negative_cases: [],
        }),
      ],
      'manifest.json',
      { type: 'application/json' },
    )
    const loadReport = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.verifier-report.v1',
          verdict: 'verified',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'single-call-authority',
          source_verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: 'different-report-digest',
            schema: 'chio.transaction.verifier-report.v1',
          },
          ui_verdict_source: 'verifier_report_ref',
          rendered_claims: [],
        }),
      ],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [
        JSON.stringify({
          schema: 'chio.transaction.verifier-report.v1',
          id: 'uploaded-verifier-report',
          verdict: 'verified',
          passport_id: 'uploaded-passport',
          passport_path: 'transaction-passport.json',
          evidence_graph_path: 'evidence-graph.json',
          verifier_policy_path: 'verifier-policy.json',
          verified_claims: [],
        }),
      ],
      'verifier/report.json',
      { type: 'application/json' },
    )

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [manifest, loadReport, verifierReport],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'load report is not bound to the manifest verifier report')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room verifier report whose bytes do not match the manifest digest', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch(servedProofRoomRoutesWithVerifierRoots())

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const declaredDigest = '0'.repeat(64)
    const manifest = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.bundle.v1',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'single-call-authority',
          verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: declaredDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          claims: [
            {
              claim_id: 'claim.transaction.passport_root_verified',
              required_artifacts: ['verifier/report.json'],
              result: 'verified',
            },
          ],
          negative_cases: [],
        }),
      ],
      'manifest.json',
      { type: 'application/json' },
    )
    const loadReport = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.verifier-report.v1',
          verdict: 'verified',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'single-call-authority',
          source_verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: declaredDigest,
            schema: 'chio.transaction.verifier-report.v1',
          },
          ui_verdict_source: 'verifier_report_ref',
          rendered_claims: [
            {
              claim_id: 'claim.transaction.passport_root_verified',
              source: 'verifier/report.json',
              verdict: 'verified',
            },
          ],
        }),
      ],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [
        JSON.stringify({
          schema: 'chio.transaction.verifier-report.v1',
          id: 'uploaded-verifier-report',
          verdict: 'verified',
          passport_id: 'uploaded-passport',
          passport_path: 'transaction-passport.json',
          evidence_graph_path: 'evidence-graph.json',
          verifier_policy_path: 'verifier-policy.json',
          verified_claims: ['claim.transaction.passport_root_verified'],
        }),
      ],
      'verifier/report.json',
      { type: 'application/json' },
    )

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [manifest, loadReport, verifierReport],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'verifier report digest does not match the manifest')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('uploaded-proof-room')
  })

  it('rejects a selected Proof Room load report that renders an unbacked claim', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?view=proof-room')
    mockFetch(servedProofRoomRoutesWithVerifierRoots())

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'served-proof-room')

    const input = container.querySelector('input[type="file"]')
    if (!input) {
      throw new Error('Proof Room file input missing')
    }

    const manifest = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.bundle.v1',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'single-call-authority',
          verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: 'uploaded-report-digest',
            schema: 'chio.transaction.verifier-report.v1',
          },
          claims: [
            {
              claim_id: 'claim.transaction.passport_root_verified',
              required_artifacts: ['verifier/report.json'],
              result: 'verified',
            },
          ],
          negative_cases: [],
        }),
      ],
      'manifest.json',
      { type: 'application/json' },
    )
    const loadReport = new File(
      [
        JSON.stringify({
          schema: 'chio.proof-room.verifier-report.v1',
          verdict: 'verified',
          bundle_id: 'uploaded-proof-room',
          fixture_id: 'single-call-authority',
          source_verifier_report_ref: {
            path: 'verifier/report.json',
            sha256: 'uploaded-report-digest',
            schema: 'chio.transaction.verifier-report.v1',
          },
          ui_verdict_source: 'verifier_report_ref',
          rendered_claims: [
            {
              claim_id: 'claim.proof_room.invented_ui_claim',
              source: 'verifier/report.json',
              verdict: 'verified',
            },
          ],
        }),
      ],
      'ui/proof-room-static/load-report.json',
      { type: 'application/json' },
    )
    const verifierReport = new File(
      [
        JSON.stringify({
          schema: 'chio.transaction.verifier-report.v1',
          id: 'uploaded-verifier-report',
          verdict: 'verified',
          passport_id: 'uploaded-passport',
          passport_path: 'transaction-passport.json',
          evidence_graph_path: 'evidence-graph.json',
          verifier_policy_path: 'verifier-policy.json',
          verified_claims: ['claim.transaction.passport_root_verified'],
        }),
      ],
      'verifier/report.json',
      { type: 'application/json' },
    )

    await act(async () => {
      Object.defineProperty(input, 'files', {
        value: [manifest, loadReport, verifierReport],
        configurable: true,
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })

    await waitForText(container, 'load report renders a claim absent from the manifest')

    expect(container.textContent).toContain('served-proof-room')
    expect(container.textContent).not.toContain('claim.proof_room.invented_ui_claim')
  })

  it('shows token guidance before issuing unauthenticated queries', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/')
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Bearer token required')

    expect(container.textContent).toContain('Bearer token required')
    expect(container.textContent).toContain('Provide a trust-control bearer token via')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('renders the empty receipt state when the corpus has no matches', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    window.history.replaceState({}, '', '/')
    vi.stubGlobal('fetch', vi.fn((input: string | URL | Request) => {
      const url = String(input)
      if (url.startsWith('/v1/receipts/query')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            totalCount: 0,
            nextCursor: null,
            receipts: [],
          }),
        })
      }
      if (url.startsWith('/v1/reports/operator')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            generatedAt: 1_700_000_000,
            filters: {},
            activity: {
              summary: {
                totalReceipts: 0,
                allowCount: 0,
                denyCount: 0,
                cancelledCount: 0,
                incompleteCount: 0,
                totalCostCharged: 0,
                totalAttemptedCost: 0,
              },
              byAgent: [],
              byTool: [],
              byTime: [],
            },
            costAttribution: {
              summary: {
                matchingReceipts: 0,
                returnedReceipts: 0,
                totalCostCharged: 0,
                totalAttemptedCost: 0,
                maxDelegationDepth: 0,
                distinctRootSubjects: 0,
                distinctLeafSubjects: 0,
                lineageGapCount: 0,
                truncated: false,
              },
              byRoot: [],
              byLeaf: [],
              receipts: [],
            },
            budgetUtilization: {
              summary: {
                matchingGrants: 0,
                returnedGrants: 0,
                distinctCapabilities: 0,
                distinctSubjects: 0,
                totalInvocations: 0,
                totalCostCharged: 0,
                nearLimitCount: 0,
                exhaustedCount: 0,
                rowsMissingScope: 0,
                rowsMissingLineage: 0,
                truncated: false,
              },
              rows: [],
            },
            compliance: {
              matchingReceipts: 0,
              evidenceReadyReceipts: 0,
              uncheckpointedReceipts: 0,
              lineageCoveredReceipts: 0,
              lineageGapReceipts: 0,
              pendingSettlementReceipts: 0,
              failedSettlementReceipts: 0,
              directEvidenceExportSupported: true,
              childReceiptScope: 'full_query_window',
              proofsComplete: true,
              exportQuery: {},
            },
          }),
        })
      }
      if (
        url.startsWith('/v1/chio/pheromone/observability')
        || url.startsWith('/v1/chio/pheromone/alerts')
        || url.startsWith('/v1/chio/pheromone/trends')
        || url.startsWith('/v1/chio/pheromone/alert-handoff')
        || url.startsWith('/v1/chio/pheromone/alert-delivery')
        || url.startsWith('/v1/chio/pheromone/alert-assurance')
      ) {
        return Promise.resolve({
          ok: false,
          status: 404,
          statusText: 'Not Found',
        })
      }
      return Promise.reject(new Error(`unexpected fetch: ${url}`))
    }))

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'No receipts found')

    expect(container.textContent).toContain('No receipts found')
  })

  it('renders the operator report summary for authenticated users', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    window.history.replaceState({}, '', '/')
    vi.stubGlobal('fetch', vi.fn((input: string | URL | Request) => {
      const url = String(input)
      if (url.startsWith('/v1/receipts/query')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            totalCount: 1,
            nextCursor: null,
            receipts: [{
              id: 'r-1',
              timestamp: 1,
              capability_id: 'cap-1',
              tool_server: 'shell',
              tool_name: 'bash',
              action: { parameters: {}, parameter_hash: 'hash' },
              decision: 'allow',
            }],
          }),
        })
      }
      if (url.startsWith('/v1/reports/operator')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            generatedAt: 1_700_000_000,
            filters: {},
            activity: {
              summary: {
                totalReceipts: 12,
                allowCount: 10,
                denyCount: 2,
                cancelledCount: 0,
                incompleteCount: 0,
                totalCostCharged: 1250,
                totalAttemptedCost: 1400,
              },
              byAgent: [],
              byTool: [],
              byTime: [],
            },
            costAttribution: {
              summary: {
                matchingReceipts: 12,
                returnedReceipts: 10,
                totalCostCharged: 1250,
                totalAttemptedCost: 1400,
                maxDelegationDepth: 2,
                distinctRootSubjects: 1,
                distinctLeafSubjects: 2,
                lineageGapCount: 0,
                truncated: false,
              },
              byRoot: [{
                rootSubjectKey: 'agent-root-abcdef0123456789',
                receiptCount: 12,
                totalCostCharged: 1250,
                totalAttemptedCost: 1400,
                distinctLeafSubjects: 2,
                maxDelegationDepth: 2,
              }],
              byLeaf: [],
              receipts: [],
            },
            budgetUtilization: {
              summary: {
                matchingGrants: 3,
                returnedGrants: 3,
                distinctCapabilities: 2,
                distinctSubjects: 2,
                totalInvocations: 12,
                totalCostCharged: 1250,
                nearLimitCount: 1,
                exhaustedCount: 0,
                rowsMissingScope: 0,
                rowsMissingLineage: 0,
                truncated: false,
              },
              rows: [],
            },
            compliance: {
              matchingReceipts: 12,
              evidenceReadyReceipts: 12,
              uncheckpointedReceipts: 0,
              checkpointCoverageRate: 1,
              lineageCoveredReceipts: 12,
              lineageGapReceipts: 0,
              lineageCoverageRate: 1,
              pendingSettlementReceipts: 1,
              failedSettlementReceipts: 0,
              directEvidenceExportSupported: true,
              childReceiptScope: 'full_query_window',
              proofsComplete: true,
              exportQuery: {},
            },
          }),
        })
      }
      if (
        url.startsWith('/v1/chio/pheromone/observability')
        || url.startsWith('/v1/chio/pheromone/alerts')
        || url.startsWith('/v1/chio/pheromone/trends')
        || url.startsWith('/v1/chio/pheromone/alert-handoff')
        || url.startsWith('/v1/chio/pheromone/alert-delivery')
        || url.startsWith('/v1/chio/pheromone/alert-assurance')
      ) {
        return Promise.resolve({
          ok: false,
          status: 404,
          statusText: 'Not Found',
        })
      }
      return Promise.reject(new Error(`unexpected fetch: ${url}`))
    }))

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Operator Report')

    expect(container.textContent).toContain('Budget Pressure')
    expect(container.textContent).toContain('Settlement And Export')
    expect(container.textContent).toContain('10 allow')
    expect(container.textContent).toContain('1 pending settlement')
  })
})
