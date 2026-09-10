"""Verify every exported receipt using separately selected trusted signers."""
import argparse
import json
from pathlib import Path
from chio.invariants import verify_receipt_with_trusted_signers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('receipts', nargs='?', type=Path, default=Path('fixtures/minimal-evidence/receipts.ndjson'))
    parser.add_argument('--trusted-signers', type=Path, default=Path('trusted-signers.json'))
    args = parser.parse_args()
    signers = json.loads(args.trusted_signers.read_text())
    if not isinstance(signers, list) or not signers or not all(isinstance(key, str) for key in signers):
        parser.error('trusted-signers must be a nonempty JSON array of public keys')
    records = [json.loads(line) for line in args.receipts.read_text().splitlines() if line.strip()]
    if not records:
        parser.error('receipt file is empty')
    results = [verify_receipt_with_trusted_signers(record.get('receipt', record), signers) for record in records]
    print(json.dumps(results, indent=2))
    return 0 if all(result['ok'] for result in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
