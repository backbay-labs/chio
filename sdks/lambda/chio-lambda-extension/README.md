# chio-lambda-extension

The Chio kernel packaged as an **AWS Lambda Extension**. Runs in-process
alongside the function handler, exposes a localhost HTTP evaluator, and
flushes receipts to DynamoDB when the Lambda execution environment is
being recycled.

## What it does

* **Registers** with the Lambda Extensions Runtime API for the `INVOKE` and
  `SHUTDOWN` lifecycle events.
* **Serves** an HTTP evaluator on `127.0.0.1:9090` that accepts JSON tool
  call descriptions, returns an allow / deny verdict with a receipt ID,
  and buffers the receipt for batch persistence.
* **Flushes** the buffered receipts to a configurable DynamoDB table when
  the `SHUTDOWN` event arrives (or when the buffer fills up).
* **Fails closed** on missing environment variables, unreachable Runtime
  API, or unreachable DynamoDB: the binary exits non-zero and the Lambda
  handler's localhost calls will error loudly instead of silently
  bypassing policy.

This crate is intentionally **outside** the main Chio Cargo workspace so it
can be versioned, released, and Lambda-layer-packaged on its own schedule.

## Configuration

| Variable               | Required | Default             | Meaning                                         |
|------------------------|----------|---------------------|-------------------------------------------------|
| `CHIO_RECEIPT_TABLE`    | yes      | _(none)_            | DynamoDB table name receipts are flushed into.  |
| `CHIO_EXTENSION_ADDR`   | no       | `127.0.0.1:9090`    | Local socket address for the evaluator.         |
| `AWS_LAMBDA_RUNTIME_API` | auto   | set by Lambda       | Advertised by the Lambda runtime at boot.       |
| `AWS_REGION` etc.      | auto     | set by Lambda       | Standard AWS SDK credential discovery.          |
| `RUST_LOG`             | no       | `chio_lambda_extension=info` | Tracing filter.                         |

## DynamoDB schema

The extension does **not** create the table; provision it in your IaC:

```yaml
ReceiptTable:
  Type: AWS::DynamoDB::Table
  Properties:
    BillingMode: PAY_PER_REQUEST
    AttributeDefinitions:
      - AttributeName: receipt_id
        AttributeType: S
      - AttributeName: timestamp
        AttributeType: N
    KeySchema:
      - AttributeName: receipt_id
        KeyType: HASH        # partition key
      - AttributeName: timestamp
        KeyType: RANGE       # sort key
```

Every item written by the extension carries:

| attribute        | type | meaning                                    |
|------------------|------|--------------------------------------------|
| `receipt_id`     | S    | UUIDv7 unique receipt identifier.          |
| `timestamp`      | N    | Unix seconds at evaluation time.           |
| `capability_id`  | S    | Capability token the call was bound to.    |
| `tool_server`    | S    | Tool server identifier.                    |
| `tool_name`      | S    | Name of the invoked tool.                  |
| `decision`       | S    | `allow` or `deny`.                         |
| `reason`         | S    | Optional deny reason.                      |
| `payload`        | S    | Canonical-JSON serialised receipt body.    |

Throttled writes (`ProvisionedThroughputExceededException`) and any items
returned in `UnprocessedItems` are retried with exponential backoff up to
five attempts, capped well under the ~2 second SHUTDOWN budget.

## Evaluator HTTP surface

The evaluator deliberately speaks a minimal JSON over HTTP/1.1 dialect so
that any language can call it with the standard library alone.

### `GET /health`, `GET /chio/health`

```json
{"status": "ok", "extension": "chio"}
```

### `POST /v1/evaluate`

Request:

```json
{
  "capability_id": "cap-01HW...",
  "tool_server":  "tools.example",
  "tool_name":    "database-query",
  "scope":        "db:read",
  "arguments":    {"sql": "SELECT 1"}
}
```

Response:

```json
{
  "receipt_id":    "01908f4a-...",
  "decision":      "allow",
  "reason":        null,
  "capability_id": "cap-01HW...",
  "tool_server":   "tools.example",
  "tool_name":     "database-query",
  "timestamp":     1713225600
}
```

A missing `capability_id` or `tool_name` deterministically returns
`"decision": "deny"` with a descriptive `reason`. More sophisticated
policy evaluation is wired in a subsequent phase (the `chio-kernel`
dependency is already pulled in so the expansion is mechanical).

## Build

```bash
# From the crate root:
cd sdks/lambda/chio-lambda-extension
CARGO_TARGET_DIR=target/lambda cargo build --release

# Run the tests:
CARGO_TARGET_DIR=target/lambda cargo test
```

### Cross-compile for Lambda

Lambda requires a Linux binary. Install the matching Rust targets and a
cross-linker:

```bash
rustup target add aarch64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu

# On macOS, install cross-linkers, e.g. via brew or the `cross` crate:
cargo install cross --git https://github.com/cross-rs/cross
```

Then:

```bash
# Build both architectures, zip them into Lambda Layer structure:
./scripts/package-layer.sh both
# -> dist/chio-extension-arm64.zip
# -> dist/chio-extension-x86_64.zip

# Or one arch at a time:
./scripts/package-layer.sh arm64
./scripts/package-layer.sh x86_64
```

The script produces a zip with the standard Lambda Extension layout:

```
extensions/chio              # the registered extension binary
bin/chio-lambda-extension    # same binary, on PATH for debugging
```

## Publish the Lambda layer

```bash
aws lambda publish-layer-version \
  --layer-name chio-kernel-extension \
  --description 'Chio protocol kernel as Lambda Extension' \
  --zip-file fileb://dist/chio-extension-arm64.zip \
  --compatible-architectures arm64 \
  --compatible-runtimes python3.11 python3.12 python3.13 nodejs20.x nodejs22.x
```

Then reference the layer ARN on your function and grant the function's
execution role `dynamodb:BatchWriteItem` on `CHIO_RECEIPT_TABLE`.

## Using from Python

Install the companion client:

```bash
pip install chio-lambda-python  # or use the in-repo workspace dep
```

```python
from chio_lambda import ChioLambdaClient, chio_tool

# Option 1: thin HTTP client
client = ChioLambdaClient()
verdict = client.evaluate(
    capability_id="cap-01HW...",
    tool_server="tools.example",
    tool_name="database-query",
    scope="db:read",
    arguments={"sql": "SELECT 1"},
)
if verdict.denied:
    return {"statusCode": 403, "body": verdict.reason}

# Option 2: decorator (evaluates before the function body runs)
@chio_tool(scope="db:read", tool_server="tools.example", tool_name="database-query")
def handler(event, context, capability_id):
    # Body only runs if evaluate() returned "allow"
    return run_query(event["body"])
```

See `../chio-lambda-python/README.md` for the full client reference.
