"""Pytest fixtures for live-broker integration tests.

The whole module is auto-skipped unless ``CHIO_INTEGRATION=1`` is set in
the environment, so a normal ``uv run pytest`` invocation never touches
a real broker. When the gate is on, each broker fixture probes its
endpoint up front and skips (with a clear message) instead of letting a
connection error noise up the failure list -- so devs who forgot to
``docker compose up`` get a one-line "broker not reachable" instead of
a backtrace tower.

Endpoints default to the ports published by ``infra/streaming-compose.yml``
(redis 16379, nats 14222) and ``infra/streaming-flink-compose.yml``
(redpanda 19092). Override via env vars (``CHIO_TEST_REDIS_URL``,
``CHIO_TEST_NATS_URL``, ``CHIO_TEST_KAFKA_BOOTSTRAP``) to point at an
alternate stack.
"""

from __future__ import annotations

import asyncio
import os
import socket
import uuid
from collections.abc import AsyncIterator, Iterator
from urllib.parse import urlparse

import pytest
import pytest_asyncio

INTEGRATION_FLAG = "CHIO_INTEGRATION"

DEFAULT_REDIS_URL = "redis://localhost:16379/0"
DEFAULT_NATS_URL = "nats://localhost:14222"
DEFAULT_KAFKA_BOOTSTRAP = "localhost:19092"

REDIS_URL_ENV = "CHIO_TEST_REDIS_URL"
NATS_URL_ENV = "CHIO_TEST_NATS_URL"
KAFKA_BOOTSTRAP_ENV = "CHIO_TEST_KAFKA_BOOTSTRAP"


def _integration_enabled() -> bool:
    return os.environ.get(INTEGRATION_FLAG, "").strip() not in ("", "0", "false", "False")


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Skip every test in this directory when the gate is off.

    Pytest collects the integration tests regardless (the ``conftest`` is
    only consulted once collection reaches this directory), but the gate
    keeps a CI run that has not opted in from accidentally hitting real
    brokers.
    """
    if _integration_enabled():
        return
    skip = pytest.mark.skip(
        reason=f"set {INTEGRATION_FLAG}=1 to run live broker integration tests"
    )
    here = os.path.dirname(__file__)
    for item in items:
        if str(item.fspath).startswith(here):
            item.add_marker(skip)


def _tcp_reachable(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def redis_url() -> str:
    return os.environ.get(REDIS_URL_ENV, DEFAULT_REDIS_URL)


@pytest_asyncio.fixture
async def redis_client(redis_url: str) -> AsyncIterator[object]:
    """Yield a connected ``redis.asyncio.Redis`` or skip if unreachable."""
    parsed = urlparse(redis_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 6379
    if not _tcp_reachable(host, port):
        pytest.skip(
            f"redis not reachable at {host}:{port}; "
            f"start `docker compose -f infra/streaming-compose.yml up -d`"
        )
    try:
        from redis.asyncio import Redis  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("redis-py not installed; `uv sync --extra redis`")

    client = Redis.from_url(redis_url, decode_responses=False)
    try:
        # Ping verifies AUTH/db selection, not just the TCP open.
        await asyncio.wait_for(client.ping(), timeout=2.0)
    except Exception as exc:  # pragma: no cover - readiness probe
        await client.aclose()
        pytest.skip(f"redis ping failed at {redis_url}: {exc}")
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def redis_unique_stream() -> str:
    """A fresh stream name per test so XADD / XACK state never collides."""
    return f"chio-it-tasks-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# NATS / JetStream
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def nats_url() -> str:
    return os.environ.get(NATS_URL_ENV, DEFAULT_NATS_URL)


@pytest_asyncio.fixture
async def nats_connection(nats_url: str) -> AsyncIterator[object]:
    """Yield a connected ``nats.NATS`` or skip if unreachable."""
    parsed = urlparse(nats_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 4222
    if not _tcp_reachable(host, port):
        pytest.skip(
            f"nats not reachable at {host}:{port}; "
            f"start `docker compose -f infra/streaming-compose.yml up -d`"
        )
    try:
        import nats  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("nats-py not installed; `uv sync --extra nats`")

    try:
        nc = await asyncio.wait_for(nats.connect(nats_url), timeout=2.0)
    except Exception as exc:  # pragma: no cover - readiness probe
        pytest.skip(f"nats connect failed at {nats_url}: {exc}")
    try:
        yield nc
    finally:
        await nc.drain()


@pytest.fixture
def nats_unique_subject_root() -> str:
    """A unique subject prefix per test so streams / consumers do not collide."""
    return f"chio_it_{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Kafka (Redpanda)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def kafka_bootstrap() -> str:
    """``host:port`` for the test Kafka cluster (Redpanda by default)."""
    return os.environ.get(KAFKA_BOOTSTRAP_ENV, DEFAULT_KAFKA_BOOTSTRAP)


@pytest.fixture
def kafka_admin(kafka_bootstrap: str) -> Iterator[object]:
    """Yield a ``confluent_kafka.admin.AdminClient`` or skip cleanly.

    Skips with a one-liner instead of crashing collection when:

    * ``confluent-kafka`` is not installed (missing ``[kafka]`` extra),
    * the bootstrap host:port is not reachable,
    * the cluster does not respond to ``list_topics`` within 5 seconds.
    """
    host, _, port_str = kafka_bootstrap.partition(":")
    try:
        port = int(port_str) if port_str else 9092
    except ValueError:
        pytest.skip(f"invalid kafka bootstrap {kafka_bootstrap!r}")
    if not _tcp_reachable(host or "localhost", port):
        pytest.skip(
            f"kafka not reachable at {kafka_bootstrap}; "
            f"start `docker compose -f infra/streaming-flink-compose.yml up -d --wait`"
        )
    try:
        from confluent_kafka.admin import AdminClient  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("confluent-kafka not installed; `uv sync --extra kafka`")

    admin = AdminClient({"bootstrap.servers": kafka_bootstrap})
    try:
        # list_topics doubles as a readiness probe; raises on broker
        # unavailable. The 5s timeout matches the Redpanda healthcheck
        # window so a flaky broker fails fast rather than hanging the
        # whole suite.
        admin.list_topics(timeout=5)
    except Exception as exc:  # pragma: no cover - readiness probe
        pytest.skip(f"kafka list_topics failed at {kafka_bootstrap}: {exc}")
    yield admin


@pytest.fixture
def kafka_topic_factory(
    kafka_admin: object,
) -> Iterator[object]:
    """Yield a callable that creates uniquely-named topics and cleans them up.

    The factory returns the topic name. Topics are tracked and deleted
    on teardown so parallel test runs do not accumulate leftover state
    across the cluster.
    """
    from confluent_kafka.admin import NewTopic  # type: ignore[import-not-found]

    created: list[str] = []

    def make(prefix: str, *, partitions: int = 1, replication: int = 1) -> str:
        # 8-hex suffix gives 16M unique names per prefix, ample for any
        # realistic test parallelism while staying short enough to read
        # in failure output.
        topic = f"chio-it-{prefix}-{uuid.uuid4().hex[:8]}"
        new = NewTopic(topic, num_partitions=partitions, replication_factor=replication)
        futures = kafka_admin.create_topics([new])  # type: ignore[attr-defined]
        # create_topics is async on the broker side; .result() waits.
        futures[topic].result(timeout=10)
        created.append(topic)
        return topic

    try:
        yield make
    finally:
        if created:
            try:
                kafka_admin.delete_topics(created, operation_timeout=10)  # type: ignore[attr-defined]
            except Exception:  # pragma: no cover - best-effort cleanup
                pass


# ---------------------------------------------------------------------------
# Flink (PyFlink local mini-cluster)
# ---------------------------------------------------------------------------


@pytest.fixture
def pyflink_module() -> object:
    """Skip if PyFlink is not importable.

    Returns the imported ``pyflink`` module. Tests that touch
    ``StreamExecutionEnvironment`` directly should depend on this
    fixture to get a clean skip when the ``[flink]`` extra is missing,
    rather than letting an ``ImportError`` bomb test collection.
    """
    try:
        import pyflink  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip(
            "apache-flink not installed; `uv sync --extra flink` (note: "
            "apache-beam needs setuptools<81 + --no-build-isolation; see README)"
        )
    return pyflink
