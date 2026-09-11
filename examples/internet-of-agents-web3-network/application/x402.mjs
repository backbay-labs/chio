/** Standard x402 v2 exact payment on the application's private EIP-3009 chain. */
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {
  createPublicClient,
  createWalletClient,
  http as transport,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import {
  encodePaymentRequiredHeader,
  decodePaymentSignatureHeader,
  encodePaymentResponseHeader,
} from "@x402/core/http";
import { ExactEvmScheme as ClientScheme } from "@x402/evm/exact/client";
import { ExactEvmScheme as FacilitatorScheme } from "@x402/evm/exact/facilitator";
import { toFacilitatorEvmSigner } from "@x402/evm";

export async function purchaseReport(context, input, directory, save) {
  const { config, provider, contract } = context;
  const file = path.join(directory, "x402-" + input.order_id + ".json");
  if (fs.existsSync(file))
    throw Error(
      "Payment intent exists; inspect its nonce and retained transaction before retrying",
    );
  assert.equal(input.amount, 10000);
  const body = input.report_json;
  assert.equal(
    crypto.createHash("sha256").update(body).digest("hex"),
    input.report_hash,
  );
  const network = "eip155:31337";
  const chain = {
    id: 31337,
    name: "Private work-order chain",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [config.endpoint] } },
  };
  const keys = JSON.parse(
    fs.readFileSync(path.join(directory, "chain-wallets.json"), "utf8"),
  );
  const payer = privateKeyToAccount(keys[2]);
  const facilitatorAccount = privateKeyToAccount(keys[0]);
  const publicClient = createPublicClient({
    chain,
    transport: transport(config.endpoint),
    pollingInterval: 50,
  });
  const walletClient = createWalletClient({
    account: facilitatorAccount,
    chain,
    transport: transport(config.endpoint),
  });
  const facilitator = new FacilitatorScheme(
    toFacilitatorEvmSigner(
      {
        address: facilitatorAccount.address,
        readContract: publicClient.readContract,
        verifyTypedData: publicClient.verifyTypedData,
        getCode: publicClient.getCode,
        writeContract: walletClient.writeContract,
        sendTransaction: walletClient.sendTransaction,
        waitForTransactionReceipt: publicClient.waitForTransactionReceipt,
      },
      { confirmationTimeoutMs: 15000 },
    ),
    { simulateInSettle: true },
  );
  const requirements = {
    scheme: "exact",
    network,
    amount: String(input.amount),
    asset: config.addresses.MockERC20,
    payTo: config.beneficiary,
    maxTimeoutSeconds: 1800,
    extra: {
      name: "Work order test dollars",
      version: "1",
      assetTransferMethod: "eip3009",
    },
  };
  const client = new x402HTTPClient(
    x402Client
      .fromConfig({
        schemes: [{ network, client: new ClientScheme(payer) }],
        spendControls: {
          allowedAssets: [
            {
              network,
              asset: requirements.asset,
              maxAmountPerPayment: "10000",
            },
          ],
        },
      })
      .registerPolicy((version, choices) =>
        choices.filter(
          (choice) =>
            version === 2 &&
            choice.network === network &&
            choice.scheme === "exact" &&
            choice.amount === "10000" &&
            choice.asset === requirements.asset &&
            choice.payTo === requirements.payTo,
        ),
      ),
  );
  let required;
  let deliveries = 0;
  let settling = false;
  const acceptedNonces = new Set();
  const exchanges = [];
  const server = http.createServer(async (request, response) => {
    const deny = (reason) => {
      exchanges.push({ status: 402, reason });
      response.writeHead(402, {
        "PAYMENT-REQUIRED": encodePaymentRequiredHeader({
          ...required,
          error: reason,
        }),
        "Content-Type": "application/json",
      });
      response.end(JSON.stringify({ error: reason }));
    };
    if (
      request.method !== "GET" ||
      request.url !== "/report/" + input.report_hash
    ) {
      response.writeHead(404);
      response.end();
      return;
    }
    const header = request.headers["payment-signature"];
    if (!header) {
      deny("Payment authorization required");
      return;
    }
    if (typeof header !== "string" || header.length > 12000) {
      deny("Invalid payment header");
      return;
    }
    let payload;
    try {
      payload = decodePaymentSignatureHeader(header);
      assert.deepEqual(payload.accepted, requirements);
      assert.deepEqual(payload.resource, required.resource);
      assert.equal(payload.x402Version, 2);
    } catch {
      deny("Payment terms or resource changed");
      return;
    }
    const nonce = payload.payload?.authorization?.nonce;
    if (settling || acceptedNonces.has(nonce)) {
      deny("Authorization already in use or delivered");
      return;
    }
    settling = true;
    try {
      const verified = await facilitator.verify(payload, requirements);
      if (!verified.isValid) {
        deny(verified.invalidReason ?? "Invalid payment authorization");
        return;
      }
      const settlement = await facilitator.settle(payload, requirements);
      if (!settlement.success) {
        deny(settlement.errorReason ?? "Payment not settled");
        return;
      }
      acceptedNonces.add(nonce);
      deliveries += 1;
      exchanges.push({ status: 200, settlement });
      response.writeHead(200, {
        "PAYMENT-RESPONSE": encodePaymentResponseHeader(settlement),
        "Content-Type": "application/json",
      });
      response.end(body);
    } catch {
      response.writeHead(503);
      response.end(
        JSON.stringify({ error: "Payment outcome requires reconciliation" }),
      );
    } finally {
      settling = false;
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const url =
    "http://127.0.0.1:" +
    server.address().port +
    "/report/" +
    input.report_hash;
  required = {
    x402Version: 2,
    resource: {
      url,
      description: "Signed review of actual escrow obligations",
      mimeType: "application/json",
    },
    accepts: [requirements],
  };
  const token = contract("MockERC20", 2);
  const balances = async () => ({
    payer: String(await token.balanceOf(config.depositor)),
    provider: String(await token.balanceOf(config.beneficiary)),
  });
  const request = (headers = {}) =>
    fetch(url, {
      headers,
      redirect: "error",
      signal: AbortSignal.timeout(20000),
    });
  try {
    const before = await balances();
    const challenge = await request();
    assert.equal(challenge.status, 402);
    const selected = client.getPaymentRequiredResponse((name) =>
      challenge.headers.get(name),
    );
    await challenge.arrayBuffer();
    const payload = await client.createPaymentPayload(selected);
    save(file, { state: "prepared", report_hash: input.report_hash, payload });
    // The official facilitator checks changed signed values. No delivery or balance change is allowed.
    for (const [name, change] of [
      [
        "amount",
        (value) => {
          value.payload.authorization.value = "10001";
        },
      ],
      [
        "beneficiary",
        (value) => {
          value.payload.authorization.to = config.depositor;
        },
      ],
      [
        "signature",
        (value) => {
          value.payload.signature = "0x" + "00".repeat(65);
        },
      ],
      [
        "network",
        (value) => {
          value.accepted.network = "eip155:1";
        },
      ],
    ]) {
      const changed = structuredClone(payload);
      change(changed);
      const response = await request(
        client.encodePaymentSignatureHeader(changed),
      );
      assert.equal(response.status, 402, name);
      await response.arrayBuffer();
      assert.deepEqual(await balances(), before, name + " moved funds");
    }
    assert.equal(deliveries, 0);
    const paid = await request(client.encodePaymentSignatureHeader(payload));
    const content = await paid.text();
    assert.equal(paid.status, 200, content);
    assert.equal(content, body);
    const settlement = client.getPaymentSettleResponse((name) =>
      paid.headers.get(name),
    );
    assert.equal(settlement.success, true);
    const transaction = await provider.getTransactionReceipt(
      settlement.transaction,
    );
    assert.equal(transaction.status, 1);
    const after = await balances();
    assert.equal(BigInt(before.payer) - BigInt(after.payer), 10000n);
    assert.equal(BigInt(after.provider) - BigInt(before.provider), 10000n);
    const replay = await request(client.encodePaymentSignatureHeader(payload));
    assert.equal(replay.status, 402);
    await replay.arrayBuffer();
    assert.deepEqual(await balances(), after);
    assert.equal(
      await token.authorizationState(
        config.depositor,
        payload.payload.authorization.nonce,
      ),
      true,
    );
    assert.equal(
      (await facilitator.verify(payload, requirements)).isValid,
      false,
      "Consumed authorization was accepted again on chain",
    );
    assert.equal(deliveries, 1);
    const result = {
      protocol: "x402",
      version: 2,
      scheme: "exact",
      sdk: "@x402/core + @x402/evm 2.25.0",
      network,
      amount: "10000",
      asset: requirements.asset,
      payer: config.depositor,
      pay_to: config.beneficiary,
      report_hash: input.report_hash,
      report: JSON.parse(content),
      payment_required: selected,
      payment_payload: payload,
      settlement,
      transaction: {
        hash: transaction.hash,
        block_hash: transaction.blockHash,
        block_number: transaction.blockNumber,
        status: transaction.status,
      },
      before,
      after,
      deliveries,
      exchanges,
    };
    save(file, { state: "settled", ...result });
    return result;
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}
