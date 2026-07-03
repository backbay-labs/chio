"""End-to-end fraud-scoring example for the Chio Flink operator.

Reads JSONL transactions from a file, evaluates each one through a
Chio capability, and routes the outputs:

* main         -> allowed transactions (PrintSink).
* RECEIPT_TAG  -> receipt envelopes (FileSink, newline-delimited).
* DLQ_TAG      -> deny envelopes (FileSink, newline-delimited).

Run locally (requires ``apache-flink`` installed):

    uv pip install 'chio-streaming[flink]'
    python examples/flink_fraud_scoring.py \\
        --input ./transactions.jsonl \\
        --receipts-out ./receipts.jsonl \\
        --dlq-out ./dlq.jsonl

A five-line sample ``transactions.jsonl``::

    {"txn_id":"t1","user":"u-1","amount":5.25,"category":"coffee"}
    {"txn_id":"t2","user":"u-2","amount":9000.00,"category":"wire"}
    {"txn_id":"t3","user":"u-3","amount":14.00,"category":"lunch"}
    {"txn_id":"t4","user":"u-4","amount":25000.0,"category":"crypto"}
    {"txn_id":"t5","user":"u-5","amount":7.99,"category":"streaming"}

Swap the FileSource for a Kafka source (commented block below) when
moving from local runs to production; nothing else in the topology
needs to change.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from chio_sdk.client import ChioClient
from pyflink.common import Time, WatermarkStrategy
from pyflink.common.serialization import SimpleStringEncoder
from pyflink.common.typeinfo import Types
from pyflink.datastream import (
    AsyncDataStream,
    CheckpointingMode,
    OutputTag,
    StreamExecutionEnvironment,
)
from pyflink.datastream.connectors.file_system import (
    FileSink,
    FileSource,
    StreamFormat,
)

from chio_streaming import DLQRouter
from chio_streaming.flink import (
    DLQ_TAG_NAME,
    RECEIPT_TAG_NAME,
    ChioAsyncEvaluateFunction,
    ChioFlinkConfig,
    ChioVerdictSplitFunction,
    register_dependencies,
)

# OutputTag instances must be reused between emission and collection,
# so they are module-level singletons here. The operator constructs
# matching tags internally via the same name + type information.
RECEIPT_TAG = OutputTag(RECEIPT_TAG_NAME, Types.PICKLED_BYTE_ARRAY())
DLQ_TAG = OutputTag(DLQ_TAG_NAME, Types.PICKLED_BYTE_ARRAY())


def build_chio_client() -> ChioClient:
    # Workers reconstruct the client inside open(), so connection-pool
    # state does not need to survive cloudpickle.
    return ChioClient("http://127.0.0.1:9090")


def build_dlq_router() -> DLQRouter:
    return DLQRouter(default_topic="chio-fraud-dlq")


def parse_event(raw: str) -> dict[str, Any]:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"_invalid": True, "raw": raw}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--receipts-out", default="./receipts.jsonl")
    parser.add_argument("--dlq-out", default="./dlq.jsonl")
    parser.add_argument("--parallelism", type=int, default=2)
    args = parser.parse_args()

    env = StreamExecutionEnvironment.get_execution_environment()
    env.set_parallelism(args.parallelism)

    # Checkpointing is mandatory for end-to-end exactly-once with
    # Flink 2PC sinks. 60s is a reasonable default; shorten for lower
    # visible-latency, lengthen to reduce coordinator load.
    env.enable_checkpointing(60_000, CheckpointingMode.EXACTLY_ONCE)

    register_dependencies(env)

    file_source = (
        FileSource.for_record_stream_format(StreamFormat.text_line_format(), args.input)
        .process_static_file_set()
        .build()
    )
    transactions = env.from_source(
        file_source,
        WatermarkStrategy.no_watermarks(),
        "file-transactions",
        type_info=Types.STRING(),
    ).map(parse_event, output_type=Types.PICKLED_BYTE_ARRAY())

    config = ChioFlinkConfig(
        capability_id="cap-fraud-scoring",
        tool_server="flink://fraud-job",
        client_factory=build_chio_client,
        dlq_router_factory=build_dlq_router,
        scope_map={"transactions": "events:consume:transactions"},
        receipt_topic="chio-fraud-receipts",
        max_in_flight=64,
        on_sidecar_error="deny",
        subject_extractor=lambda _event: "transactions",
    )

    evaluated = AsyncDataStream.unordered_wait(
        transactions,
        ChioAsyncEvaluateFunction(config),
        Time.milliseconds(10_000),
        128,
        Types.PICKLED_BYTE_ARRAY(),
    )

    split = evaluated.process(ChioVerdictSplitFunction())
    receipts = split.get_side_output(RECEIPT_TAG)
    dlq = split.get_side_output(DLQ_TAG)

    split.print("allowed")

    receipts.map(lambda b: b.decode("utf-8"), output_type=Types.STRING()).sink_to(
        FileSink.for_row_format(args.receipts_out, SimpleStringEncoder()).build()
    ).name("chio-receipt-sink")
    dlq.map(lambda b: b.decode("utf-8"), output_type=Types.STRING()).sink_to(
        FileSink.for_row_format(args.dlq_out, SimpleStringEncoder()).build()
    ).name("chio-dlq-sink")


    env.execute("chio-flink-fraud-scoring")


if __name__ == "__main__":
    main()
