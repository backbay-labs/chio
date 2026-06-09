# chio-streaming developer targets.
#
# Unit tests run against in-memory broker doubles and need no infra.
# Integration tests run against a live broker stack and are gated by
# CHIO_INTEGRATION=1 (see tests/integration/conftest.py).

# Resolve the repo root so the compose file path works regardless of
# where `make` was invoked from.
REPO_ROOT       := $(shell git rev-parse --show-toplevel)
COMPOSE         := docker compose -f $(REPO_ROOT)/deploy/compose/streaming-compose.yml
COMPOSE_FLINK   := docker compose -f $(REPO_ROOT)/deploy/compose/streaming-flink-compose.yml

# Flink Kafka connector JAR is staged here. PyFlink 2.2 ships KafkaSource
# wiring in its Python wheel but the connector classes for KafkaSink
# require an external JAR. The integration tests skip cleanly when the
# JAR is absent; this target stages it once for the suite.
TEST_JAR_DIR    := $(CURDIR)/.test-jars
KAFKA_JAR_VER   := 4.0.1-2.0
KAFKA_JAR_NAME  := flink-sql-connector-kafka-$(KAFKA_JAR_VER).jar
KAFKA_JAR_URL   := https://repo.maven.apache.org/maven2/org/apache/flink/flink-sql-connector-kafka/$(KAFKA_JAR_VER)/$(KAFKA_JAR_NAME)

.PHONY: help test test-integration test-integration-flink test-integration-all \
        infra-up infra-down infra-logs \
        infra-flink-up infra-flink-down infra-flink-logs \
        flink-jars

help:
	@echo "Targets:"
	@echo "  test                    Unit tests (no broker required)"
	@echo "  test-integration        Bring up Redis + NATS, run live tests, tear down"
	@echo "  test-integration-flink  Bring up Redpanda + Flink, run Flink/Kafka live tests, tear down"
	@echo "  test-integration-all    Run both integration suites against their respective stacks"
	@echo "  infra-up                Start the Redis + NATS broker stack"
	@echo "  infra-down              Stop the Redis + NATS stack and drop volumes"
	@echo "  infra-logs              Tail Redis + NATS logs"
	@echo "  infra-flink-up          Start the Redpanda + Flink stack and stage Flink JARs"
	@echo "  infra-flink-down        Stop the Redpanda + Flink stack and drop volumes"
	@echo "  infra-flink-logs        Tail Redpanda + Flink logs"
	@echo "  flink-jars              Download the Flink Kafka connector JAR (idempotent)"

test:
	uv run pytest -v

infra-up:
	$(COMPOSE) up -d --wait

infra-down:
	$(COMPOSE) down -v

infra-logs:
	$(COMPOSE) logs -f

# Brings up brokers, runs the live-broker suite, and tears down even on
# failure (the trap fires before `make` exits non-zero).
test-integration:
	$(COMPOSE) up -d --wait
	@trap '$(COMPOSE) down -v' EXIT; \
	  CHIO_INTEGRATION=1 \
	  CHIO_TEST_REDIS_URL=redis://localhost:16379/0 \
	  CHIO_TEST_NATS_URL=nats://localhost:14222 \
	  uv run pytest tests/integration/test_redis_streams_integration.py tests/integration/test_nats_integration.py -v

# ---------------------------------------------------------------------------
# Flink + Kafka integration
# ---------------------------------------------------------------------------

# One-shot JAR fetch. Idempotent: skips the download if the file is
# already staged. Lets the Flink integration test find the connector
# JAR without paying for a 9MB download per test invocation.
flink-jars:
	@mkdir -p $(TEST_JAR_DIR)
	@if [ ! -f $(TEST_JAR_DIR)/$(KAFKA_JAR_NAME) ]; then \
	  echo "Fetching $(KAFKA_JAR_NAME)..."; \
	  curl -fsSL -o $(TEST_JAR_DIR)/$(KAFKA_JAR_NAME) $(KAFKA_JAR_URL); \
	else \
	  echo "$(KAFKA_JAR_NAME) already staged"; \
	fi

infra-flink-up: flink-jars
	$(COMPOSE_FLINK) up -d --wait

infra-flink-down:
	$(COMPOSE_FLINK) down -v

infra-flink-logs:
	$(COMPOSE_FLINK) logs -f

# Brings up Redpanda + (dockerised) Flink, stages JARs, runs the
# Flink + Kafka live tests, and tears down even on failure. The
# Flink test itself runs PyFlink in-process via LocalStreamEnvironment;
# the dockerised Flink JobManager / TaskManager are brought up only as
# a UI / manual exploration target (http://localhost:18081).
test-integration-flink: flink-jars
	$(COMPOSE_FLINK) up -d --wait
	@trap '$(COMPOSE_FLINK) down -v' EXIT; \
	  CHIO_INTEGRATION=1 \
	  CHIO_TEST_KAFKA_BOOTSTRAP=localhost:19092 \
	  uv run pytest \
	    tests/integration/test_kafka_middleware_integration.py \
	    tests/integration/test_flink_kafka_integration.py \
	    -v

# Convenience umbrella: runs both integration suites against their
# respective stacks. Each leg cleans up its own stack via the trap
# above before the next leg starts.
test-integration-all:
	$(MAKE) test-integration
	$(MAKE) test-integration-flink
