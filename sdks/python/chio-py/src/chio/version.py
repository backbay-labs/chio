PACKAGE_NAME = "chio-sdk"
__version__ = "0.1.0"


def default_client_info() -> dict[str, str]:
    return {"name": PACKAGE_NAME, "version": __version__}
