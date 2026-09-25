"""Operator-priced, bounded checks offered by this application."""

OFFERS = {
    "hotfix-review": {
        "price_minor": 45_000,
        "max_files": 10,
        "max_bytes": 200_000,
        "checks": ["python-call-patterns"],
    },
    "release-review": {
        "price_minor": 125_000,
        "max_files": 100,
        "max_bytes": 2_000_000,
        "checks": ["python-call-patterns", "exception-handling"],
    },
    "release-plus-cloud-review": {
        "price_minor": 175_000,
        "max_files": 100,
        "max_bytes": 2_000_000,
        "checks": ["python-call-patterns", "exception-handling", "json-exposure-settings"],
    },
    "full-estate-review": {
        "price_minor": 325_000,
        "max_files": 500,
        "max_bytes": 5_000_000,
        "checks": [
            "python-call-patterns",
            "exception-handling",
            "json-exposure-settings",
            "dependency-pins",
        ],
    },
}


def offer(scope):
    if scope not in OFFERS:
        raise ValueError("Unsupported review scope; choose an offer from provider/catalog.py")
    return OFFERS[scope]
