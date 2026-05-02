# AWS Bedrock Architecture

The listing architecture has three trust zones:

1. Customer AWS account in `us-east-1`: owns the Bedrock integration role.
2. Chio control plane: validates entitlement, evaluates policy, signs
   receipts, and prepares metering events.
3. AWS services: Bedrock Runtime and AWS Marketplace SaaS APIs.

Traffic enters Chio first. The customer role is assumed only after the
tenant entitlement and IAM principal binding pass. Receipt overage is sent
from the Chio seller account through Marketplace metering APIs.

`architecture.svg` is the diagram source submitted to AWS security review.
