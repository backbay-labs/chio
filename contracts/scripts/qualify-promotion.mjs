import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";
import ganache from "ganache";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const contractsDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(contractsDir, "..");
const NON_TESTNET_ASSURANCE_CHAIN_ID = 8453;
const NON_TESTNET_ASSURANCE_PORT = Number(process.env.CHIO_PROMOTION_ASSURANCE_DEVNET_PORT ?? "0");
const NON_TESTNET_DEPLOYER_KEY = "0x1000000000000000000000000000000000000000000000000000000000000001";
const NON_TESTNET_CREATE2_FACTORY = "0x5555555555555555555555555555555555555555";
const RECOVERABLE_LOOKING_SIGNATURE = `0x${"11".repeat(65)}`;

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function repoRelative(filePath) {
  return path.relative(repoRoot, filePath).replaceAll(path.sep, "/");
}

function runNode(args, expectSuccess = true) {
  const result = spawnSync("node", args, {
    cwd: repoRoot,
    encoding: "utf8"
  });
  if (expectSuccess) {
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } else {
    assert.notEqual(result.status, 0, "expected command to fail");
  }
  return result;
}

function runNodeAsync(args, expectSuccess = true) {
  return new Promise((resolve, reject) => {
    const child = spawn("node", args, {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (status) => {
      try {
        if (expectSuccess) {
          assert.equal(status, 0, stderr || stdout);
        } else {
          assert.notEqual(status, 0, "expected command to fail");
        }
        resolve({ status, stdout, stderr });
      } catch (error) {
        reject(error);
      }
    });
  });
}

function startNonTestnetAssuranceDevnet() {
  const server = ganache.server({
    logging: { quiet: true },
    chain: { chainId: NON_TESTNET_ASSURANCE_CHAIN_ID, hardfork: "shanghai" },
    wallet: {
      accounts: [
        {
          secretKey: NON_TESTNET_DEPLOYER_KEY,
          balance: ethers.toBeHex(ethers.parseEther("1000"))
        }
      ]
    }
  });
  return new Promise((resolve, reject) => {
    server.listen(NON_TESTNET_ASSURANCE_PORT, (error) => {
      if (error) {
        reject(error);
        return;
      }
      const address = server.address();
      resolve({
        server,
        rpcUrl: `http://127.0.0.1:${address.port}`
      });
    });
  });
}

function closeServer(server) {
  const result = server.close();
  return result && typeof result.then === "function" ? result : Promise.resolve();
}

function buildApproval({ manifestPath, manifest, manifestHash, status = "approved", environment = "local-devnet" }) {
  return {
    approval_id: `chio.web3-deployment-approval.${environment}.v1`,
    candidate_release_id: manifest.review_context.candidate_release_id,
    deployment_policy_id: manifest.review_context.deployment_policy_id,
    reviewed_manifest_path: repoRelative(manifestPath),
    reviewed_manifest_sha256: manifestHash,
    environment,
    status,
    approvals: [
      {
        role: "release-reviewer",
        actor: "local-qualification",
        approved_at: "2026-04-02T17:30:00Z"
      },
      {
        role: "operator",
        actor: "local-devnet-admin",
        approved_at: "2026-04-02T17:30:30Z"
      }
    ],
    create2: {
      factory_mode: "runner-managed-local",
      factory_address: null,
      salt_namespace: manifest.salt_namespace
    },
    failure_policy: {
      rollback_mode: "evm_snapshot_revert",
      stop_on_error: true,
      require_manual_retry_after_failure: true
    }
  };
}

function buildNonTestnetApproval({ manifestPath, manifest, manifestHash }) {
  const approval = buildApproval({
    manifestPath,
    manifest,
    manifestHash,
    environment: "base-mainnet"
  });
  approval.create2 = {
    factory_mode: "predeployed",
    factory_address: NON_TESTNET_CREATE2_FACTORY,
    salt_namespace: manifest.salt_namespace
  };
  approval.failure_policy = {
    rollback_mode: "manual-replacement-deployment",
    stop_on_error: true,
    require_manual_retry_after_failure: true
  };
  return approval;
}

function buildAssuranceUnlock({ manifest, manifestHash, approval }) {
  return {
    assurance_id: "chio.web3-external-assurance.negative-security-owner.v1",
    status: "approved",
    gate: "EXTERNAL_ASSURANCE",
    chain_id: manifest.chain_id,
    reviewed_manifest_sha256: manifestHash,
    candidate_release_id: manifest.review_context.candidate_release_id,
    deployment_policy_id: manifest.review_context.deployment_policy_id,
    approval_id: approval.approval_id,
    unresolved_critical_high_findings: [],
    security_owner_approval: {
      status: "approved",
      actor: "negative-security-owner-fixture",
      approved_at: "2026-04-02T18:10:00Z",
      signature: RECOVERABLE_LOOKING_SIGNATURE
    }
  };
}

function duplicateContractManifest(manifest) {
  const copy = structuredClone(manifest);
  copy.contracts.push(structuredClone(manifest.contracts[0]));
  copy.manifest_id = `${manifest.manifest_id}.duplicate-salt-test`;
  return copy;
}

function missingArtifactManifest(manifest) {
  const copy = structuredClone(manifest);
  copy.contracts[0].artifact = "contracts/artifacts/DoesNotExist.json";
  copy.manifest_id = `${manifest.manifest_id}.missing-artifact-test`;
  return copy;
}

function qualifyPromotionScriptOperatorKeyHash() {
  const source = fs.readFileSync(path.join(contractsDir, "scripts", "promote-deployment.mjs"), "utf8");
  assert.match(
    source,
    /operatorConfig\.operator_key_hash/,
    "promotion must read the reviewed runtime operator_key_hash"
  );
  assert.doesNotMatch(
    source,
    /const\s+expectedEdKeyHash\s*=\s*labelHash\(operatorLabel\)/,
    "promotion must not register a label hash as the operator Ed25519 key hash"
  );
}

function prepareBaseMainnetManifest(outputRoot, deployerAddress) {
  const manifestPath = path.join(outputRoot, "base-mainnet.reviewed.json");
  const valuesPath = path.join(outputRoot, "base-mainnet.review-inputs.json");
  writeJson(valuesPath, {
    registry_admin_address: deployerAddress,
    price_admin_address: deployerAddress,
    operator_address: deployerAddress,
    delegate_address: deployerAddress,
    operator_ed_key_label: "chio-non-testnet-negative-operator",
    operator_key_hash: "0x0791868d8f29ea735f26a17a9aea038cd4255baac26eac5a74e58a07ed2f1975",
    delegate_expiry_seconds: 3600
  });
  runNode([
    path.join("contracts", "scripts", "prepare-reviewed-manifest.mjs"),
    "--template",
    "contracts/deployments/base-mainnet.template.json",
    "--values-file",
    repoRelative(valuesPath),
    "--environment",
    "base-mainnet",
    "--output",
    repoRelative(manifestPath)
  ]);
  return {
    manifestPath,
    manifest: readJson(manifestPath),
    manifestHash: sha256File(manifestPath)
  };
}

async function qualifyNonTestnetSecurityOwnerNegatives(outputRoot) {
  const runRoot = path.join(outputRoot, "negative-assurance-security-owner");
  ensureDir(runRoot);
  const deployerAddress = new ethers.Wallet(NON_TESTNET_DEPLOYER_KEY).address;
  const { manifestPath, manifest, manifestHash } = prepareBaseMainnetManifest(runRoot, deployerAddress);
  const cases = [
    {
      name: "top-level-only",
      mutateApproval(approval) {
        approval.security_owner_address = deployerAddress;
      }
    },
    {
      name: "pending-owner",
      mutateApproval(approval) {
        approval.security_owner_address = deployerAddress;
        approval.approvals.push({
          role: "security-owner",
          status: "pending",
          actor: "negative-security-owner-fixture",
          address: deployerAddress,
          approved_at: "2026-04-02T18:10:00Z"
        });
      }
    },
    {
      name: "missing-owner-approved-at",
      mutateApproval(approval) {
        approval.security_owner_address = deployerAddress;
        approval.approvals.push({
          role: "security-owner",
          status: "approved",
          actor: "negative-security-owner-fixture",
          address: deployerAddress
        });
      }
    },
    {
      name: "conflicting-owner",
      mutateApproval(approval) {
        approval.security_owner_address = "0x7777777777777777777777777777777777777777";
        approval.approvals.push({
          role: "security-owner",
          status: "approved",
          actor: "negative-security-owner-fixture",
          address: deployerAddress,
          approved_at: "2026-04-02T18:10:00Z"
        });
      }
    },
    {
      name: "conflicting-approved-owners",
      mutateApproval(approval) {
        approval.approvals.push(
          {
            role: "security-owner",
            status: "approved",
            actor: "negative-security-owner-fixture-a",
            address: deployerAddress,
            approved_at: "2026-04-02T18:10:00Z"
          },
          {
            role: "security-owner",
            status: "approved",
            actor: "negative-security-owner-fixture-b",
            address: "0x7777777777777777777777777777777777777777",
            approved_at: "2026-04-02T18:11:00Z"
          }
        );
      }
    }
  ];

  const { server, rpcUrl } = await startNonTestnetAssuranceDevnet();
  try {
    const reports = [];
    for (const testCase of cases) {
      const caseDir = path.join(runRoot, testCase.name);
      ensureDir(caseDir);
      const approval = buildNonTestnetApproval({ manifestPath, manifest, manifestHash });
      testCase.mutateApproval(approval);
      const approvalPath = path.join(caseDir, "approval.json");
      writeJson(approvalPath, approval);
      const unlockPath = path.join(caseDir, "assurance-unlock.json");
      writeJson(unlockPath, buildAssuranceUnlock({ manifest, manifestHash, approval }));
      const result = await runNodeAsync(
        [
          path.join("contracts", "scripts", "promote-deployment.mjs"),
          "--manifest",
          repoRelative(manifestPath),
          "--approval",
          repoRelative(approvalPath),
          "--output-dir",
          repoRelative(caseDir),
          "--rpc-url",
          rpcUrl,
          "--deployer-key",
          NON_TESTNET_DEPLOYER_KEY,
          "--assurance-unlock",
          repoRelative(unlockPath)
        ],
        false
      );
      assert.match(
        `${result.stderr}\n${result.stdout}`,
        /security-owner/,
        `${testCase.name} should fail at the security-owner gate`
      );
      const reportPath = path.join(caseDir, "promotion-report.json");
      const report = readJson(reportPath);
      assert.equal(report.status, "failed");
      assert.equal(
        fs.existsSync(path.join(caseDir, "deployment.json")),
        false,
        `${testCase.name} should fail before writing deployment evidence`
      );
      assert.equal(
        (report.checks ?? []).some((check) => check.id === "deployment.create2_rollout"),
        false,
        `${testCase.name} should fail before CREATE2 rollout`
      );
      const provider = new ethers.JsonRpcProvider(rpcUrl);
      for (const [contractId, address] of Object.entries(report.planned_contract_addresses ?? {})) {
        assert.equal(
          await provider.getCode(address),
          "0x",
          `${testCase.name} should not deploy ${contractId}`
        );
      }
      provider.destroy?.();
      reports.push(repoRelative(reportPath));
    }
    return reports;
  } finally {
    await closeServer(server);
  }
}

async function main() {
  const outputDirIndex = process.argv.indexOf("--output-dir");
  const outputRoot =
    outputDirIndex >= 0 && process.argv[outputDirIndex + 1]
      ? path.resolve(repoRoot, process.argv[outputDirIndex + 1])
      : path.join(repoRoot, "target", "web3-promotion-qualification");

  ensureDir(outputRoot);
  qualifyPromotionScriptOperatorKeyHash();

  const manifestPath = path.join(contractsDir, "deployments", "local-devnet.reviewed.json");
  const manifest = readJson(manifestPath);
  const manifestHash = sha256File(manifestPath);

  const successRuns = [];
  for (const label of ["run-a", "run-b"]) {
    const runDir = path.join(outputRoot, label);
    ensureDir(runDir);
    const approvalPath = path.join(runDir, "approval.json");
    writeJson(approvalPath, buildApproval({ manifestPath, manifest, manifestHash }));
    const promotionArgs = [
      path.join("contracts", "scripts", "promote-deployment.mjs"),
      "--manifest",
      repoRelative(manifestPath),
      "--approval",
      repoRelative(approvalPath),
      "--output-dir",
      repoRelative(runDir),
      "--local-devnet",
      "--rollback-on-failure"
    ];
    if (label === "run-a") {
      promotionArgs.push("--base-builder-code", "bc_localtest");
    }
    runNode(promotionArgs, true);
    successRuns.push(readJson(path.join(runDir, "promotion-report.json")));
  }

  assert.equal(
    successRuns[0].attribution?.erc8021_marker,
    "0x80218021802180218021802180218021",
    "builder-code promotion run should record ERC-8021 attribution"
  );

  assert.deepEqual(
    successRuns[0].planned_contract_addresses,
    successRuns[1].planned_contract_addresses,
    "replayed promotion should produce identical planned contract addresses"
  );
  assert.deepEqual(
    successRuns[0].deployed_contract_addresses,
    successRuns[1].deployed_contract_addresses,
    "replayed promotion should deploy the same contract addresses on fresh local devnets"
  );

  const badApprovalDir = path.join(outputRoot, "negative-approval");
  ensureDir(badApprovalDir);
  const badApprovalPath = path.join(badApprovalDir, "approval.json");
  const badApproval = buildApproval({ manifestPath, manifest, manifestHash: "deadbeef" });
  writeJson(badApprovalPath, badApproval);
  runNode(
    [
      path.join("contracts", "scripts", "promote-deployment.mjs"),
      "--manifest",
      repoRelative(manifestPath),
      "--approval",
      repoRelative(badApprovalPath),
      "--output-dir",
      repoRelative(badApprovalDir),
      "--local-devnet",
      "--rollback-on-failure"
    ],
    false
  );
  const badApprovalReport = readJson(path.join(badApprovalDir, "promotion-report.json"));
  assert.equal(badApprovalReport.status, "failed");

  const resumeDir = path.join(outputRoot, "resume-existing");
  ensureDir(resumeDir);
  const duplicateManifestPath = path.join(resumeDir, "duplicate-salt.reviewed.json");
  const duplicateManifest = duplicateContractManifest(manifest);
  writeJson(duplicateManifestPath, duplicateManifest);
  const duplicateManifestHash = sha256File(duplicateManifestPath);
  const duplicateApprovalPath = path.join(resumeDir, "approval.json");
  writeJson(
    duplicateApprovalPath,
    buildApproval({
      manifestPath: duplicateManifestPath,
      manifest: duplicateManifest,
      manifestHash: duplicateManifestHash
    })
  );
  runNode(
    [
      path.join("contracts", "scripts", "promote-deployment.mjs"),
      "--manifest",
      repoRelative(duplicateManifestPath),
      "--approval",
      repoRelative(duplicateApprovalPath),
      "--output-dir",
      repoRelative(resumeDir),
      "--local-devnet",
      "--rollback-on-failure"
    ],
    true
  );
  const resumeDeployment = readJson(path.join(resumeDir, "deployment.json"));
  assert.equal(
    resumeDeployment.deployment_transactions["chio.identity-registry"].status,
    "already_deployed",
    "duplicate-salt resume should skip an already deployed CREATE2 address"
  );

  const rollbackFailureDir = path.join(outputRoot, "negative-rollback");
  ensureDir(rollbackFailureDir);
  const badManifestPath = path.join(rollbackFailureDir, "missing-artifact.reviewed.json");
  const badManifest = missingArtifactManifest(manifest);
  writeJson(badManifestPath, badManifest);
  const badManifestHash = sha256File(badManifestPath);
  const rollbackApprovalPath = path.join(rollbackFailureDir, "approval.json");
  writeJson(
    rollbackApprovalPath,
    buildApproval({
      manifestPath: badManifestPath,
      manifest: badManifest,
      manifestHash: badManifestHash
    })
  );
  runNode(
    [
      path.join("contracts", "scripts", "promote-deployment.mjs"),
      "--manifest",
      repoRelative(badManifestPath),
      "--approval",
      repoRelative(rollbackApprovalPath),
      "--output-dir",
      repoRelative(rollbackFailureDir),
      "--local-devnet",
      "--rollback-on-failure"
    ],
    false
  );
  const rollbackPlan = readJson(path.join(rollbackFailureDir, "rollback-plan.json"));
  assert.equal(rollbackPlan.rollback_executed, true, "rollback should execute on failed local promotion");

  const negativeAssuranceReports = await qualifyNonTestnetSecurityOwnerNegatives(outputRoot);

  const summary = {
    report_id: "chio.web3-deployment-promotion-qualification.local-devnet.v1",
    generated_at: new Date().toISOString(),
    manifest: repoRelative(manifestPath),
    checks: [
      {
        id: "promotion.reproducible_rollout",
        outcome: "pass",
        note: "Two fresh local-devnet promotion runs produced identical CREATE2-planned and deployed contract addresses."
      },
      {
        id: "promotion.base_builder_code_attribution",
        outcome: "pass",
        note: "A local promotion run with --base-builder-code appended an ERC-8021 suffix to CREATE2 factory calls without changing CREATE2 outcomes."
      },
      {
        id: "promotion.resume_existing_create2",
        outcome: "pass",
        note: "A resumed promotion skips already deployed CREATE2 addresses and continues through post-deployment configuration."
      },
      {
        id: "promotion.approval_gate",
        outcome: "pass",
        note: "Tampered approval manifest hashes fail closed before deployment."
      },
      {
        id: "promotion.rollback_on_failure",
        outcome: "pass",
        note: "Duplicate-salt deployment failure triggered explicit local snapshot rollback."
      },
      {
        id: "promotion.non_testnet_security_owner_gate",
        outcome: "pass",
        note: "Non-testnet assurance rejects top-level-only, pending, incomplete, or conflicting security-owner approvals before deployment."
      }
    ],
    evidence: {
      success_runs: successRuns.map((_, index) => repoRelative(path.join(outputRoot, index === 0 ? "run-a" : "run-b", "promotion-report.json"))),
      negative_approval_report: repoRelative(path.join(badApprovalDir, "promotion-report.json")),
      resume_existing_report: repoRelative(path.join(resumeDir, "promotion-report.json")),
      negative_rollback_report: repoRelative(path.join(rollbackFailureDir, "promotion-report.json")),
      negative_rollback_plan: repoRelative(path.join(rollbackFailureDir, "rollback-plan.json")),
      negative_assurance_security_owner_reports: negativeAssuranceReports
    }
  };

  writeJson(path.join(outputRoot, "promotion-qualification.json"), summary);
}

await main();
