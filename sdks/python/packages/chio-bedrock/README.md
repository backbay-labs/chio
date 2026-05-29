# chio-bedrock

`chio-bedrock` is the Python distribution wrapper for the AWS Bedrock
listing. It presents a small `BedrockChioClient` surface over
an injected Bedrock runtime client, emits Chio receipt-shaped records, and
prepares Marketplace metering callbacks.

The Rust Bedrock adapter remains the source of truth for production
transport. This package is the Python SDK shape consumed by listing
examples and customer onboarding tests.

## Example

```python
from chio_bedrock import BedrockChioClient

client = BedrockChioClient(
    bedrock_runtime=my_bedrock_runtime_client,
    principal_arn="arn:aws:sts::111122223333:assumed-role/chio-bedrock/example",
    account_id="111122223333",
)

invocation = client.converse(
    tenant_id="tenant-a",
    capability_id="cap-bedrock-a",
    model_id="anthropic.claude-3-haiku-20240307-v1:0",
    messages=[{"role": "user", "content": [{"text": "hello"}]}],
)
```

The returned invocation contains:

- `response`: the Bedrock response object.
- `receipt`: a Chio receipt-compatible dictionary.
- `metering`: a Marketplace metering callback payload.

The SDK currently supports only the `us-east-1` region.
