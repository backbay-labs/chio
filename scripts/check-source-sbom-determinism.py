#!/usr/bin/env python3
"""Compare actual source inventories while retaining generated Syft run identities."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys
from uuid import UUID


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def normalized(document: dict) -> dict:
    require(isinstance(document, dict), 'source SBOM must be an object')
    require(document.get('bomFormat') == 'CycloneDX' and document.get('specVersion') == '1.6',
            'expected CycloneDX 1.6 source SBOM')
    metadata = document.get('metadata', {})
    require(isinstance(metadata, dict) and isinstance(metadata.get('component'), dict),
            'missing source metadata')
    require(metadata['component'].get('type') == 'file'
            and metadata['component'].get('name') == '.'
            and 'version' not in metadata['component'], 'expected the dir:. source scan')
    require(isinstance(document.get('components'), list) and bool(document['components']),
            'source inventory is empty')
    serial = document.get('serialNumber')
    require(isinstance(serial, str) and f'urn:uuid:{UUID(serial)}' == serial,
            'invalid generated serial number')
    stamp = metadata.get('timestamp')
    require(isinstance(stamp, str) and datetime.fromisoformat(stamp).tzinfo is not None,
            'invalid generated timestamp')
    result = copy.deepcopy(document)
    # These are Syft-generated run metadata, not package identities or graph content.
    del result['serialNumber']
    del result['metadata']['timestamp']
    return result


def compare(first: Path, second: Path) -> dict:
    raw = [path.read_bytes() for path in (first, second)]
    documents = [json.loads(value, object_pairs_hook=unique_pairs) for value in raw]
    values = [normalized(document) for document in documents]
    canonical = [json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
                 for value in values]
    require(canonical[0] == canonical[1],
            'source inventory differs beyond generated serialNumber and timestamp')
    return {'schema': 'chio.source-sbom-determinism.v1', 'passed': True,
            'firstSha256': hashlib.sha256(raw[0]).hexdigest(),
            'secondSha256': hashlib.sha256(raw[1]).hexdigest(),
            'normalizedSha256': hashlib.sha256(canonical[0]).hexdigest(),
            'excludedGeneratedFields': ['serialNumber', 'metadata.timestamp'],
            'inventoryComponents': len(values[0]['components'])}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--first', type=Path, required=True)
    parser.add_argument('--second', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(args.report.resolve() not in {args.first.resolve(), args.second.resolve()},
                'report must differ from inputs')
        args.report.unlink(missing_ok=True)
        result = compare(args.first, args.second)
        args.report.write_text(json.dumps(result, indent=2) + '\n')
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f'Source SBOM comparison refused: {error}', file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
