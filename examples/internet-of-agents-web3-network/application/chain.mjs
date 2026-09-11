/** Local EVM execution using the actual Chio escrow and registry contracts. */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import solc from "solc";
import {
  AbiCoder,
  Contract,
  ContractFactory,
  JsonRpcProvider,
  NonceManager,
  Wallet,
  keccak256,
  toUtf8Bytes,
} from "ethers";

const home = path.dirname(fileURLToPath(import.meta.url));
const mode = process.argv[2];
let ownedServer = null;
let stage = "initialize";
const directory = path.resolve(process.argv[3] ?? ".");
const load = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const sha = (text) => crypto.createHash("sha256").update(text).digest("hex");
function save(file, value) {
  const temporary = file + "." + crypto.randomUUID();
  const descriptor = fs.openSync(temporary, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, JSON.stringify(value, null, 2));
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temporary, file);
}
function compile() {
  const root = fs.existsSync(path.join(home, "contracts/src"))
    ? path.join(home, "contracts")
    : path.resolve(home, "../../../contracts");
  const sources = {};
  const visit = (relative) => {
    for (const entry of fs.readdirSync(path.join(root, relative), {
      withFileTypes: true,
    })) {
      const file = path.join(relative, entry.name);
      if (entry.isDirectory()) visit(file);
      else if (file.endsWith(".sol"))
        sources[file] = {
          content: fs.readFileSync(path.join(root, file), "utf8"),
        };
    }
  };
  visit("src");
  sources["LocalPaymentToken.sol"] = {
    content: fs.readFileSync(path.join(home, "LocalPaymentToken.sol"), "utf8"),
  };
  const input = {
    language: "Solidity",
    sources,
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "paris",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };
  const result = JSON.parse(solc.compile(JSON.stringify(input)));
  const failures =
    result.errors?.filter((item) => item.severity === "error") ?? [];
  if (failures.length)
    throw Error(failures.map((item) => item.formattedMessage).join("\n"));
  return {
    source_hash: sha(JSON.stringify(sources)),
    contracts: result.contracts,
  };
}
async function connect() {
  const config = load(path.join(directory, "chain.json"));
  if (
    !/^http:\/\/127\.0\.0\.1:\d+$/.test(config.endpoint) ||
    config.chain_id !== 31337
  )
    throw Error("This application only executes its private local chain");
  const provider = new JsonRpcProvider(config.endpoint, 31337, {
    staticNetwork: true,
  });
  provider.pollingInterval = 50;
  const wallets = load(path.join(directory, "chain-wallets.json")).map(
    (seed) => new Wallet(seed, provider),
  );
  const signers = wallets.map((wallet) => new NonceManager(wallet));
  const contracts = load(path.join(directory, "chain-contracts.json"));
  const contract = (name, index) =>
    new Contract(config.addresses[name], contracts[name].abi, signers[index]);
  return { config, provider, wallets, signers, contract };
}
function transactionRecord(receipt) {
  return {
    transaction_hash: receipt.hash,
    block_number: receipt.blockNumber,
    block_hash: receipt.blockHash,
    status: receipt.status,
    logs: receipt.logs.map((log) => ({
      address: log.address,
      topics: [...log.topics],
      data: log.data,
    })),
  };
}
function injectedInterruption(point) {
  const file = path.join(directory, "chain-interruption.json");
  if (fs.existsSync(file) && load(file).point === point) {
    fs.unlinkSync(file);
    throw Error(
      "Qualification interruption after actual chain publication: " + point,
    );
  }
}
async function reconcile(order, file, context) {
  const escrow = context.contract("ChioEscrow", 3);
  const observed = await escrow.getEscrow(order.escrow_id);
  const deposited = Number(observed.deposited),
    released = Number(observed.released);
  if (deposited > 0) {
    for (const [key, value] of Object.entries(order.terms)) {
      if (
        String(observed.terms[key]).toLowerCase() !==
        String(value).toLowerCase()
      )
        throw Error("Retained escrow intent differs from the on-chain terms");
    }
    const logs = await context.provider.getLogs({
      address: context.config.addresses.ChioEscrow,
      topics: [null, order.escrow_id],
      fromBlock: 0,
      toBlock: "latest",
    });
    for (const log of logs) {
      if (
        !order.transactions.some(
          (item) => item.transaction_hash === log.transactionHash,
        )
      ) {
        const receipt = await context.provider.getTransactionReceipt(
          log.transactionHash,
        );
        if (!receipt || receipt.status !== 1)
          throw Error("Escrow event has no successful transaction");
        order.transactions.push(transactionRecord(receipt));
      }
    }
    order.state = observed.refunded
      ? "refunded"
      : released === deposited
        ? "released"
        : released > 0
          ? "partial"
          : "funded";
  }
  order.observed = {
    deposited,
    released,
    refunded: observed.refunded,
    block_number: await context.provider.getBlockNumber(),
    chain_id: context.config.chain_id,
    escrow_contract: context.config.addresses.ChioEscrow,
    source_hash: context.config.source_hash,
  };
  save(file, order);
  return order;
}
async function recover(order, file, context) {
  const previous = order.pending_action ?? order.state;
  order.pending_action = previous;
  await reconcile(order, file, context);
  const { config, contract, signers } = context;
  const escrow = contract("ChioEscrow", 3),
    token = contract("MockERC20", 2);
  // Resume only the already persisted intent; the caller cannot change terms,
  // amount, receipt, beneficiary or checkpoint during recovery.
  if (previous === "funding" && order.observed.deposited === 0) {
    order.transactions.push(
      await transact(
        token.approve(config.addresses.ChioEscrow, order.terms.maxAmount),
      ),
    );
    save(file, order);
    order.transactions.push(
      await transact(escrow.connect(signers[2]).createEscrow(order.terms)),
    );
    order.state = "funded";
    save(file, order);
  } else if (previous === "releasing" && order.observed.released === 0) {
    const release = order.release;
    if (!release) throw Error("No persisted release intent to recover");
    const registry = contract("ChioRootRegistry", 1);
    const entry = await registry.getRoot(config.operator, release.sequence);
    if (Number(entry.checkpointSeq) === 0) {
      order.transactions.push(
        await transact(
          registry.publishRoot(
            config.operator,
            release.root,
            release.sequence,
            release.sequence,
            release.sequence,
            1,
            config.operator_key_hash,
          ),
        ),
      );
      save(file, order);
    } else if (
      entry.merkleRoot !== release.root ||
      entry.operatorKeyHash !== config.operator_key_hash
    )
      throw Error("Checkpoint differs from the persisted release intent");
    const method = release.partial
      ? "partialReleaseWithProofDetailed"
      : "releaseWithProofDetailed";
    order.transactions.push(
      await transact(
        escrow[method](
          order.escrow_id,
          { auditPath: [], leafIndex: 0, treeSize: 1 },
          release.root,
          "0x" + release.receipt_id,
          release.amount,
        ),
      ),
    );
    order.state = release.partial ? "partial" : "released";
    save(file, order);
  } else if (previous === "refunding" && !order.observed.refunded) {
    order.transactions.push(
      await transact(escrow.connect(signers[2]).refund(order.escrow_id)),
    );
    order.state = "refunded";
    save(file, order);
  }
  await reconcile(order, file, context);
  delete order.pending_action;
  order.recovery = {
    previous_state: previous,
    reconciled_state: order.state,
    observed_block: order.observed.block_number,
  };
  save(file, order);
  return order;
}
async function transact(transaction) {
  const response = await transaction;
  const receipt = await response.wait();
  if (receipt.status !== 1)
    throw Error("Transaction reverted: " + response.hash);
  return transactionRecord(receipt);
}
async function serve() {
  const { default: ganache } = await import("ganache");
  const walletsFile = path.join(directory, "chain-wallets.json");
  if (!fs.existsSync(walletsFile))
    save(
      walletsFile,
      Array.from({ length: 4 }, () => Wallet.createRandom().privateKey),
    );
  const keys = load(walletsFile);
  const server = ganache.server({
    chain: { chainId: 31337 },
    wallet: {
      accounts: keys.map((secretKey) => ({
        secretKey,
        balance: "0x3635c9adc5dea00000",
      })),
    },
    database: { dbPath: path.join(directory, "chain-db") },
    logging: { quiet: true },
  });
  ownedServer = server;
  await server.listen(0, "127.0.0.1");
  const endpoint = "http://127.0.0.1:" + server.address().port;
  const previous = path.join(directory, "chain.json");
  if (fs.existsSync(previous)) {
    const config = load(previous);
    config.endpoint = endpoint;
    save(previous, config);
  } else {
    const provider = new JsonRpcProvider(endpoint, 31337, {
      staticNetwork: true,
    });
    provider.pollingInterval = 50;
    const wallets = keys.map((key) => new Wallet(key, provider));
    const signers = wallets.map((wallet) => new NonceManager(wallet));
    const built = compile();
    const selected = {};
    for (const entries of Object.values(built.contracts))
      for (const [name, value] of Object.entries(entries))
        if (
          [
            "ChioIdentityRegistry",
            "ChioRootRegistry",
            "ChioEscrow",
            "LocalPaymentToken",
          ].includes(name)
        )
          selected[name === "LocalPaymentToken" ? "MockERC20" : name] = value;
    const transactions = [];
    const addresses = {};
    const deploy = async (name, args) => {
      stage = "deploy " + name;
      console.error(stage);
      const value = await new ContractFactory(
        selected[name].abi,
        "0x" + selected[name].evm.bytecode.object,
        signers[0],
      ).deploy(...args);
      transactions.push(
        await transact(Promise.resolve(value.deploymentTransaction())),
      );
      addresses[name] = await value.getAddress();
      save(path.join(directory, "chain-setup-progress.json"), {
        addresses,
        transactions,
      });
      return value;
    };
    const identity = await deploy("ChioIdentityRegistry", [wallets[0].address]);
    const registry = await deploy("ChioRootRegistry", [
      await identity.getAddress(),
    ]);
    const escrow = await deploy("ChioEscrow", [
      await registry.getAddress(),
      await identity.getAddress(),
      wallets[0].address,
    ]);
    const token = await deploy("MockERC20", []);
    const kernel = load(path.join(directory, "config.json")).trusted_kernel;
    const operatorKeyHash = "0x" + sha(Buffer.from(kernel, "hex"));
    const binding = await wallets[0].signTypedData(
      {
        name: "ChioIdentityRegistry",
        version: "1",
        chainId: 31337,
        verifyingContract: await identity.getAddress(),
      },
      {
        ChioOperatorBinding: [
          { name: "operatorAddress", type: "address" },
          { name: "edKeyHash", type: "bytes32" },
          { name: "settlementKey", type: "address" },
        ],
      },
      {
        operatorAddress: wallets[1].address,
        edKeyHash: operatorKeyHash,
        settlementKey: wallets[1].address,
      },
    );
    stage = "register operator";
    transactions.push(
      await transact(
        identity.registerOperator(
          wallets[1].address,
          operatorKeyHash,
          wallets[1].address,
          binding,
        ),
      ),
    );
    stage = "allow token";
    transactions.push(
      await transact(escrow.setTokenAllowed(await token.getAddress(), true)),
    );
    stage = "mint local token";
    transactions.push(
      await transact(token.mint(wallets[2].address, 1_000_000)),
    );
    save(path.join(directory, "chain-contracts.json"), selected);
    save(previous, {
      schema: "work-order.chain.v1",
      chain_id: 31337,
      endpoint,
      addresses,
      operator_key_hash: operatorKeyHash,
      operator: wallets[1].address,
      depositor: wallets[2].address,
      beneficiary: wallets[3].address,
      source_hash: built.source_hash,
      setup_transactions: transactions,
    });
    provider.destroy();
  }
  save(path.join(directory, "chain-ready.json"), { endpoint });
  console.error("Local Chio escrow chain listening at " + endpoint);
  let closing = false;
  const close = async () => {
    if (closing) return;
    closing = true;
    await server.close();
    process.exit(0);
  };
  process.on("SIGTERM", close);
  process.on("SIGINT", close);
}
function leaf(config, escrowId, receipt, amount, partial) {
  return keccak256(
    AbiCoder.defaultAbiCoder().encode(
      [
        "bytes32",
        "uint256",
        "address",
        "bytes32",
        "address",
        "address",
        "bytes32",
        "bytes32",
        "uint256",
        "bool",
      ],
      [
        keccak256(
          toUtf8Bytes(
            "ChioEscrowProof(uint256 chainId,address escrow,bytes32 escrowId,address token,address beneficiary,bytes32 operatorKeyHash,bytes32 receiptHash,uint256 amount,bool partial)",
          ),
        ),
        31337,
        config.addresses.ChioEscrow,
        escrowId,
        config.addresses.MockERC20,
        config.beneficiary,
        config.operator_key_hash,
        receipt,
        amount,
        partial,
      ],
    ),
  );
}
async function execute(input) {
  const context = await connect();
  const { config, provider, contract } = context;
  try {
    if (input.action === "buy_report") {
      const { purchaseReport } = await import("./x402.mjs");
      return await purchaseReport(context, input, directory, save);
    }
    const token = contract("MockERC20", 2);
    const escrow = contract("ChioEscrow", input.action === "refund" ? 2 : 3);
    const registry = contract("ChioRootRegistry", 1);
    const location = path.join(directory, "chain-orders");
    fs.mkdirSync(location, { recursive: true, mode: 0o700 });
    if (!/^[a-zA-Z0-9-]{1,80}$/.test(input.order_id))
      throw Error("Invalid work order ID");
    const file = path.join(location, input.order_id + ".json");
    if (input.action === "fund") {
      if (fs.existsSync(file))
        throw Error("Order already funded; inspect its retained transaction");
      if (
        !Number.isSafeInteger(input.amount) ||
        input.amount < 1 ||
        input.amount > 300000
      )
        throw Error("Amount outside bounded work order");
      const block = await provider.getBlock("latest");
      const terms = {
        capabilityId: "0x" + sha(input.capability_id + ":" + input.order_id),
        depositor: config.depositor,
        beneficiary: config.beneficiary,
        token: config.addresses.MockERC20,
        maxAmount: input.amount,
        deadline: block.timestamp + 300,
        operator: config.operator,
        operatorKeyHash: config.operator_key_hash,
      };
      const escrowId = await escrow.deriveEscrowId(terms);
      // Persist intent before publishing. Recovery inspects this exact escrow;
      // it never creates a second escrow or chooses a replacement order ID.
      const order = {
        order_id: input.order_id,
        terms,
        escrow_id: escrowId,
        transactions: [],
        state: "funding",
      };
      save(file, order);
      order.transactions.push(
        await transact(
          token.approve(config.addresses.ChioEscrow, input.amount),
        ),
      );
      save(file, order);
      order.transactions.push(
        await transact(escrow.connect(context.signers[2]).createEscrow(terms)),
      );
      injectedInterruption("after-create");
      order.state = "funded";
      save(file, order);
      return order;
    }
    const order = load(file);
    if (input.action === "recover") return await recover(order, file, context);
    if (input.action === "release") {
      if (
        !/^[0-9a-f]{64}$/.test(input.receipt_id) ||
        !Number.isSafeInteger(input.amount) ||
        input.amount < 1 ||
        input.amount > order.terms.maxAmount
      )
        throw Error("Invalid exact receipt or amount");
      if (order.state !== "funded")
        throw Error("Order is not awaiting release");
      const partial = input.amount < order.terms.maxAmount;
      const receipt = "0x" + input.receipt_id;
      const root = leaf(
        config,
        order.escrow_id,
        receipt,
        input.amount,
        partial,
      );
      const sequenceFile = path.join(directory, "root-sequence.json");
      const seq = fs.existsSync(sequenceFile) ? load(sequenceFile).next : 1;
      save(sequenceFile, { next: seq + 1 });
      order.state = "releasing";
      order.release = {
        receipt_id: input.receipt_id,
        amount: input.amount,
        partial,
        root,
        sequence: seq,
      };
      save(file, order);
      order.transactions.push(
        await transact(
          registry.publishRoot(
            config.operator,
            root,
            seq,
            seq,
            seq,
            1,
            config.operator_key_hash,
          ),
        ),
      );
      save(file, order);
      injectedInterruption("after-root");
      const method = partial
        ? "partialReleaseWithProofDetailed"
        : "releaseWithProofDetailed";
      const balanceBefore = (
        await token.balanceOf(config.beneficiary)
      ).toString();
      const controls = [];
      for (const [name, action] of [
        [
          "altered receipt hash",
          () =>
            escrow[method].staticCall(
              order.escrow_id,
              { auditPath: [], leafIndex: 0, treeSize: 1 },
              root,
              "0x" + "00".repeat(32),
              input.amount,
            ),
        ],
        [
          "wrong beneficiary caller",
          () =>
            escrow
              .connect(context.signers[2])
              [
                method
              ].staticCall(order.escrow_id, { auditPath: [], leafIndex: 0, treeSize: 1 }, root, receipt, input.amount),
        ],
      ]) {
        let refused = false;
        try {
          await action();
        } catch (error) {
          if (error.code !== "CALL_EXCEPTION") throw error;
          refused = true;
          controls.push({
            case: name,
            result: "contract reverted",
            error: error.revert?.name ?? error.shortMessage,
          });
        }
        if (!refused)
          throw Error("Contract admitted negative control: " + name);
      }
      const balanceAfter = (
        await token.balanceOf(config.beneficiary)
      ).toString();
      if (balanceBefore !== balanceAfter)
        throw Error("A proof control changed the beneficiary balance");
      order.proof_controls = {
        calls: controls,
        balance_before: balanceBefore,
        balance_after: balanceAfter,
      };
      save(file, order);
      order.transactions.push(
        await transact(
          escrow[method](
            order.escrow_id,
            { auditPath: [], leafIndex: 0, treeSize: 1 },
            root,
            receipt,
            input.amount,
          ),
        ),
      );
      injectedInterruption("after-release");
      order.state = partial ? "partial" : "released";
      save(file, order);
      return order;
    }
    if (input.action === "refund") {
      if (order.state !== "partial" && order.state !== "funded")
        throw Error("Order has no refundable balance");
      // Time travel is specific to this local test chain and is recorded.
      const block = await provider.getBlock("latest");
      const seconds = Math.max(0, order.terms.deadline - block.timestamp + 1);
      await provider.send("evm_increaseTime", [seconds]);
      await provider.send("evm_mine", []);
      order.state = "refunding";
      save(file, order);
      order.transactions.push(await transact(escrow.refund(order.escrow_id)));
      injectedInterruption("after-refund");
      order.state = "refunded";
      order.local_clock_advance_seconds = seconds;
      save(file, order);
      return order;
    }
    if (input.action === "status")
      return {
        ...order,
        source_hash: config.source_hash,
        chain_id: config.chain_id,
        escrow_contract: config.addresses.ChioEscrow,
        beneficiary_balance: (
          await token.balanceOf(config.beneficiary)
        ).toString(),
        buyer_balance: (await token.balanceOf(config.depositor)).toString(),
        escrow_balance: (
          await token.balanceOf(config.addresses.ChioEscrow)
        ).toString(),
      };
    throw Error("Unknown local chain action");
  } finally {
    provider.destroy();
  }
}
try {
  if (mode === "serve") await serve();
  else if (mode === "execute") {
    let input = "";
    for await (const chunk of process.stdin) {
      input += chunk;
      if (input.length > 262144) throw Error("Input too large");
    }
    console.log(JSON.stringify(await execute(JSON.parse(input))));
  } else
    throw Error(
      "Usage: node chain.mjs serve HOST_DIRECTORY | execute HOST_DIRECTORY < request.json",
    );
} catch (error) {
  console.error(
    JSON.stringify({
      stage,
      message: error.shortMessage ?? error.message,
      detail: error.info ?? null,
    }),
  );
  if (ownedServer) await ownedServer.close();
  process.exitCode = 1;
}
