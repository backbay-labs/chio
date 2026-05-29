#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SDK_PYTHON_SRC = Path(__file__).resolve().parents[4] / "sdks" / "python" / "chio-py" / "src"
if str(SDK_PYTHON_SRC) not in sys.path:
    sys.path.insert(0, str(SDK_PYTHON_SRC))

from chio import (
    NestedCallbackRouter,
    ChioClient,
    ChioSession,
    elicitation_accept_result,
    exchange_access_token as sdk_exchange_access_token,
    resolve_oauth_access_token,
    roots_list_result,
    sampling_text_result,
)
from chio.models import TransportResponse
from chio.transport import (
    post_rpc as sdk_post_rpc,
    terminal_message as sdk_terminal_message,
)

if "--help" in sys.argv:
    print("Chio Python conformance client")
    raise SystemExit(0)

ARGS = {}
argv = sys.argv[1:]
for index in range(0, len(argv), 2):
    flag = argv[index]
    value = argv[index + 1] if index + 1 < len(argv) else None
    if not flag.startswith("--") or value is None:
        raise SystemExit(f"invalid arguments near {flag}")
    key = flag[2:].replace("-", "_")
    ARGS[key] = value

for required in ("base_url", "auth_token", "scenarios_dir", "results_output", "artifacts_dir"):
    if required not in ARGS:
        raise SystemExit(f"missing required argument --{required.replace('_', '-')}")
ARGS.setdefault("auth_mode", "static-bearer")
ARGS.setdefault("auth_scope", "mcp:invoke")

CONFORMANCE_SAMPLE_TEXT = "sampled by conformance peer"
CONFORMANCE_ELICITED_CONTENT = {"answer": "elicited by conformance peer"}
CONFORMANCE_ROOTS = [
    {
        "uri": "file:///workspace/conformance-root",
        "name": "conformance-root",
    }
]
CONFORMANCE_CLIENT_CAPABILITIES = {
    "sampling": {
        "context": {},
        "tools": {},
    },
    "elicitation": {
        "form": {},
        "url": {},
    },
    "roots": {
        "listChanged": True,
    },
}


def collect_json_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.json") if path.is_file())


def load_scenarios(root: Path) -> list[dict]:
    return [json.loads(path.read_text()) for path in collect_json_files(root)]


def scenario_requires_dedicated_session(scenario: dict) -> bool:
    return str(scenario.get("id", "")).startswith("nested-")


def transport_response_to_dict(response: TransportResponse) -> dict:
    return {
        "request": response.request,
        "status": response.status,
        "headers": response.headers,
        "messages": response.messages,
    }


def post_rpc(
    base_url: str,
    auth_token: str,
    body: dict,
    session_id: str | None = None,
    protocol_version: str | None = None,
    on_message=None,
) -> dict:
    return transport_response_to_dict(
        sdk_post_rpc(
            client=None,
            base_url=base_url,
            auth_token=auth_token,
            body=body,
            session_id=session_id,
            protocol_version=protocol_version,
            on_message=on_message,
        )
    )

def delete_session(session: ChioSession) -> int:
    return session.close()


def terminal_message(messages: list[dict], expected_id: int) -> dict:
    return sdk_terminal_message(messages, expected_id)


def scenario_result(scenario: dict, duration_ms: int, status: str, assertions: list[dict]) -> dict:
    return {
        "scenarioId": scenario["id"],
        "peer": "python",
        "peerRole": "client_to_chio_server",
        "deploymentMode": "remote_http",
        "transport": "streamable-http",
        "specVersion": scenario.get("specVersions", ["2025-11-25"])[0],
        "category": scenario["category"],
        "status": status,
        "durationMs": duration_ms,
        "assertions": assertions,
        "expectedFailure": status == "xfail",
    }


def passed_result(scenario: dict, duration_ms: int, assertion_name: str) -> dict:
    return scenario_result(
        scenario,
        duration_ms,
        "pass",
        [{"name": assertion_name, "status": "pass"}],
    )


def failed_result(scenario: dict, duration_ms: int, assertion_name: str, message: str) -> dict:
    result = scenario_result(
        scenario,
        duration_ms,
        "fail",
        [{"name": assertion_name, "status": "fail", "message": message}],
    )
    result["failureKind"] = "assertion-failed"
    result["failureMessage"] = message
    return result


def exception_result(scenario: dict, message: str, duration_ms: int = 0) -> dict:
    result = scenario_result(
        scenario,
        duration_ms,
        "fail",
        [{"name": "scenario_execution", "status": "fail", "message": message}],
    )
    result["failureKind"] = "exception"
    result["failureMessage"] = message
    return result


def xfailed_result(scenario: dict, duration_ms: int, assertion_name: str, message: str) -> dict:
    result = scenario_result(
        scenario,
        duration_ms,
        "xfail",
        [{"name": assertion_name, "status": "fail", "message": message}],
    )
    result["notes"] = scenario.get("notes", message)
    result["failureKind"] = "expected-failure"
    result["failureMessage"] = message
    result["expectedFailure"] = True
    return result


def resolve_auth(transcript: list[dict]) -> dict:
    if ARGS["auth_mode"] != "oauth-local":
        return {"mode": "static-bearer", "access_token": ARGS["auth_token"]}
    oauth_context = resolve_oauth_access_token(
        base_url=ARGS["base_url"],
        auth_scope=ARGS["auth_scope"],
        emit=transcript.append,
    )
    return {
        "mode": "oauth-local",
        "access_token": oauth_context["access_token"],
        "protected_resource_metadata": oauth_context["protected_resource_metadata"],
        "authorization_server_metadata": oauth_context["authorization_server_metadata"],
    }


def initialize_session(
    base_url: str, auth_token: str, transcript: list[dict], step_prefix: str = ""
) -> ChioSession:
    for attempt in range(30):
        try:
            nested_router = build_nested_callback_router(transcript)
            client = ChioClient.with_static_bearer(base_url, auth_token)
            session = client.initialize(
                capabilities=CONFORMANCE_CLIENT_CAPABILITIES,
                client_info={
                    "name": "chio-conformance-python",
                    "version": "0.1.0",
                },
                on_message=lambda message, session: nested_router.handle(
                    message,
                    session,
                    step_prefix=f"{step_prefix}notifications/initialized/nested",
                ),
            )
            transcript.append(
                {
                    "step": f"{step_prefix}initialize",
                    "request": session.handshake.initialize_response.request,
                    "httpStatus": session.handshake.initialize_response.status,
                    "headers": session.handshake.initialize_response.headers,
                    "messages": session.handshake.initialize_response.messages,
                }
            )
            transcript.append(
                {
                    "step": f"{step_prefix}notifications/initialized",
                    "request": session.handshake.initialized_response.request,
                    "httpStatus": session.handshake.initialized_response.status,
                    "messages": session.handshake.initialized_response.messages,
                }
            )
            return session
        except Exception as error:  # noqa: BLE001
            if attempt == 29:
                raise error
            time.sleep(0.1)
    raise RuntimeError("unreachable initialize retry path")


def build_nested_callback_router(transcript: list[dict]) -> NestedCallbackRouter:
    return (
        NestedCallbackRouter(emit=transcript.append)
        .register(
            "sampling/createMessage",
            step_suffix="sampling-response",
            builder=lambda message, _session: sampling_text_result(
                message,
                text=CONFORMANCE_SAMPLE_TEXT,
                model="chio-conformance-python-model",
            ),
        )
        .register(
            "elicitation/create",
            step_suffix="elicitation-response",
            builder=lambda message, _session: elicitation_accept_result(
                message,
                content=(
                    None
                    if message.get("params", {}).get("mode") == "url"
                    else CONFORMANCE_ELICITED_CONTENT
                ),
            ),
        )
        .register(
            "roots/list",
            step_suffix="roots-response",
            builder=lambda message, _session: roots_list_result(
                message,
                roots=CONFORMANCE_ROOTS,
            ),
        )
    )


def run_scenario(
    scenario: dict, auth_context: dict, session: ChioSession, transcript: list[dict]
) -> dict:
    started = time.time()
    session_auth_token = auth_context["access_token"]
    nested_router = build_nested_callback_router(transcript)
    try:
        if scenario["id"] == "initialize":
            return passed_result(scenario, int((time.time() - started) * 1000), "initialize_succeeds")

        if scenario["id"] == "auth-unauthorized-challenge":
            request = urllib.request.Request(
                f"{ARGS['base_url']}/mcp",
                data=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 20,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": {
                                "name": "chio-conformance-python-unauthorized",
                                "version": "0.1.0",
                            },
                        },
                    }
                ).encode("utf-8"),
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "unauthorized_initialize_returns_resource_metadata_challenge",
                    "unauthorized initialize unexpectedly succeeded",
                )
            except urllib.error.HTTPError as error:
                body = error.read().decode("utf-8")
                headers = {key.lower(): value for key, value in error.headers.items()}
                transcript.append(
                    {
                        "step": "auth/unauthorized-challenge",
                        "httpStatus": error.code,
                        "headers": headers,
                        "body": body,
                    }
                )
                challenge = headers.get("www-authenticate", "")
                if error.code != 401 or "resource_metadata=" not in challenge:
                    return failed_result(
                        scenario,
                        int((time.time() - started) * 1000),
                        "unauthorized_initialize_returns_resource_metadata_challenge",
                        "unauthorized initialize did not return a protected-resource challenge",
                    )
                return passed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "unauthorized_initialize_returns_resource_metadata_challenge",
                )

        if scenario["id"] == "auth-protected-resource-metadata":
            metadata = auth_context.get("protected_resource_metadata", {})
            servers = metadata.get("authorization_servers", [])
            scopes = metadata.get("scopes_supported", [])
            if not servers or ARGS["auth_scope"] not in scopes:
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "protected_resource_metadata_advertises_auth_server_and_scope",
                    "protected resource metadata did not advertise the expected auth server and scope",
                )
            return passed_result(
                scenario,
                int((time.time() - started) * 1000),
                "protected_resource_metadata_advertises_auth_server_and_scope",
            )

        if scenario["id"] == "auth-authorization-server-metadata":
            metadata = auth_context.get("authorization_server_metadata", {})
            grants = metadata.get("grant_types_supported", [])
            if (
                "authorization_code" not in grants
                or "urn:ietf:params:oauth:grant-type:token-exchange" not in grants
                or not metadata.get("authorization_endpoint")
                or not metadata.get("token_endpoint")
            ):
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "authorization_server_metadata_advertises_expected_grants",
                    "authorization server metadata did not advertise the expected grant types and endpoints",
                )
            return passed_result(
                scenario,
                int((time.time() - started) * 1000),
                "authorization_server_metadata_advertises_expected_grants",
            )

        if scenario["id"] == "auth-code-initialize":
            extra_session = initialize_session(
                ARGS["base_url"], auth_context["access_token"], transcript, "auth-code/"
            )
            delete_status = delete_session(extra_session)
            transcript.append({"step": "auth-code/delete-session", "httpStatus": delete_status})
            return passed_result(
                scenario,
                int((time.time() - started) * 1000),
                "authorization_code_access_token_initializes_session",
            )

        if scenario["id"] == "auth-token-exchange-initialize":
            exchanged_token = sdk_exchange_access_token(
                base_url=ARGS["base_url"],
                auth_scope=ARGS["auth_scope"],
                authorization_server_metadata=auth_context["authorization_server_metadata"],
                access_token=auth_context["access_token"],
                emit=transcript.append,
            )
            exchanged_session = initialize_session(
                ARGS["base_url"], exchanged_token, transcript, "token-exchange/"
            )
            delete_status = delete_session(exchanged_session)
            transcript.append({"step": "token-exchange/delete-session", "httpStatus": delete_status})
            return passed_result(
                scenario,
                int((time.time() - started) * 1000),
                "token_exchange_access_token_initializes_session",
            )

        if scenario["id"] == "resources-subscribe-updated-notification":
            subscribed_uri = "fixture://docs/alpha"
            subscribe_response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {"jsonrpc": "2.0", "id": 40, "method": "resources/subscribe", "params": {"uri": subscribed_uri}},
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "resources/subscribe", "request": subscribe_response["request"], "httpStatus": subscribe_response["status"], "messages": subscribe_response["messages"]})
            terminal_message(subscribe_response["messages"], 40)
            if subscribe_response["status"] != 200:
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "resources_subscribe_succeeds",
                    "resources/subscribe did not succeed",
                )

            trigger_response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {
                    "jsonrpc": "2.0",
                    "id": 41,
                    "method": "tools/call",
                    "params": {
                        "name": "emit_fixture_notifications",
                        "arguments": {"uri": subscribed_uri},
                    },
                },
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "notifications/trigger-updated", "request": trigger_response["request"], "httpStatus": trigger_response["status"], "messages": trigger_response["messages"]})
            terminal_message(trigger_response["messages"], 41)
            update_delivered = any(
                message.get("method") == "notifications/resources/updated"
                and message.get("params", {}).get("uri") == subscribed_uri
                for message in trigger_response["messages"]
            )
            if trigger_response["status"] != 200 or not update_delivered:
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "subscribed_resource_update_is_forwarded",
                    "wrapped notification flow did not deliver notifications/resources/updated for the subscribed URI",
                )

            return scenario_result(
                scenario,
                int((time.time() - started) * 1000),
                "pass",
                [
                    {"name": "resources_subscribe_succeeds", "status": "pass"},
                    {"name": "subscribed_resource_update_is_forwarded", "status": "pass"},
                ],
            )

        if scenario["id"] == "catalog-list-changed-notifications":
            trigger_response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {
                    "jsonrpc": "2.0",
                    "id": 42,
                    "method": "tools/call",
                    "params": {
                        "name": "emit_fixture_notifications",
                        "arguments": {"uri": "fixture://docs/alpha"},
                    },
                },
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "notifications/trigger-catalog", "request": trigger_response["request"], "httpStatus": trigger_response["status"], "messages": trigger_response["messages"]})
            terminal_message(trigger_response["messages"], 42)
            methods = {
                message.get("method")
                for message in trigger_response["messages"]
                if message.get("method")
            }
            has_all = (
                "notifications/resources/list_changed" in methods
                and "notifications/tools/list_changed" in methods
                and "notifications/prompts/list_changed" in methods
            )
            if trigger_response["status"] != 200 or not has_all:
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "catalog_list_changed_notifications_are_forwarded",
                    "wrapped notification flow did not deliver the expected list-changed notifications",
                )

            return passed_result(
                scenario,
                int((time.time() - started) * 1000),
                "catalog_list_changed_notifications_are_forwarded",
            )

        if scenario["id"] == "tools-list":
            response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "tools/list", "request": response["request"], "httpStatus": response["status"], "messages": response["messages"]})
            message = terminal_message(response["messages"], 2)
            tools = message.get("result", {}).get("tools", [])
            if response["status"] != 200 or not any(tool.get("name") == "echo_text" for tool in tools):
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "tools_list_contains_echo_text",
                    "tools/list did not include echo_text",
                )
            return passed_result(scenario, int((time.time() - started) * 1000), "tools_list_contains_echo_text")

        if scenario["id"] == "tools-call-simple-text":
            response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "echo_text",
                        "arguments": {"message": "hello from python peer"},
                    },
                },
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "tools/call", "request": response["request"], "httpStatus": response["status"], "messages": response["messages"]})
            message = terminal_message(response["messages"], 3)
            text = (
                message.get("result", {})
                .get("content", [{}])[0]
                .get("text")
            )
            if response["status"] != 200 or text != "hello from python peer":
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "tool_result_matches_input_text",
                    f"unexpected tool text result: {text!r}",
                )
            return passed_result(scenario, int((time.time() - started) * 1000), "tool_result_matches_input_text")

        if scenario["id"] == "resources-list":
            response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}},
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "resources/list", "request": response["request"], "httpStatus": response["status"], "messages": response["messages"]})
            message = terminal_message(response["messages"], 4)
            resources = message.get("result", {}).get("resources", [])
            if response["status"] != 200 or not any(resource.get("uri") == "fixture://docs/alpha" for resource in resources):
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "resources_list_contains_fixture_uri",
                    "resources/list did not include fixture://docs/alpha",
                )
            return passed_result(scenario, int((time.time() - started) * 1000), "resources_list_contains_fixture_uri")

        if scenario["id"] == "prompts-list":
            response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {"jsonrpc": "2.0", "id": 5, "method": "prompts/list", "params": {}},
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "prompts/list", "request": response["request"], "httpStatus": response["status"], "messages": response["messages"]})
            message = terminal_message(response["messages"], 5)
            prompts = message.get("result", {}).get("prompts", [])
            if response["status"] != 200 or not any(prompt.get("name") == "summarize_fixture" for prompt in prompts):
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "prompts_list_contains_fixture_prompt",
                    "prompts/list did not include summarize_fixture",
                )
            return passed_result(scenario, int((time.time() - started) * 1000), "prompts_list_contains_fixture_prompt")

        if scenario["id"] == "tasks-call-get-result":
            create = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "echo_text",
                        "arguments": {"message": "hello from python task peer"},
                        "task": {},
                    },
                },
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "tasks/tools-call", "request": create["request"], "httpStatus": create["status"], "messages": create["messages"]})
            create_message = terminal_message(create["messages"], 6)
            task_id = create_message.get("result", {}).get("task", {}).get("taskId")
            if create["status"] != 200 or not task_id:
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "task_created",
                    "task-augmented tools/call did not return a task id",
                )

            get_response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {"jsonrpc": "2.0", "id": 7, "method": "tasks/get", "params": {"taskId": task_id}},
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "tasks/get", "request": get_response["request"], "httpStatus": get_response["status"], "messages": get_response["messages"]})
            task_get = terminal_message(get_response["messages"], 7)
            get_status = task_get.get("result", {}).get("status")
            if get_response["status"] != 200 or get_status not in ("working", "completed"):
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "tasks_get_returns_working_or_completed",
                    f"unexpected tasks/get status: {get_status!r}",
                )

            result_response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {"jsonrpc": "2.0", "id": 8, "method": "tasks/result", "params": {"taskId": task_id}},
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "tasks/result", "request": result_response["request"], "httpStatus": result_response["status"], "messages": result_response["messages"]})
            task_result = terminal_message(result_response["messages"], 8)
            related_task_id = (
                task_result.get("result", {})
                .get("_meta", {})
                .get("io.modelcontextprotocol/related-task", {})
                .get("taskId")
            )
            text = (
                task_result.get("result", {})
                .get("content", [{}])[0]
                .get("text")
            )
            if (
                result_response["status"] != 200
                or related_task_id != task_id
                or text != "hello from python task peer"
            ):
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "tasks_result_returns_related_terminal_payload",
                    "tasks/result did not return the expected related-task metadata or payload",
                )

            return scenario_result(
                scenario,
                int((time.time() - started) * 1000),
                "pass",
                [
                    {"name": "task_created", "status": "pass"},
                    {"name": "tasks_get_returns_working_or_completed", "status": "pass"},
                    {"name": "tasks_result_returns_related_terminal_payload", "status": "pass"},
                ],
            )

        if scenario["id"] == "tasks-cancel":
            create = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {
                        "name": "slow_echo",
                        "arguments": {"message": "hello from python cancel peer"},
                        "task": {},
                    },
                },
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "tasks/cancel-create", "request": create["request"], "httpStatus": create["status"], "messages": create["messages"]})
            create_message = terminal_message(create["messages"], 9)
            task_id = create_message.get("result", {}).get("task", {}).get("taskId")
            if create["status"] != 200 or not task_id:
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "task_created",
                    "task-augmented slow tools/call did not return a task id",
                )

            cancel_response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {"jsonrpc": "2.0", "id": 10, "method": "tasks/cancel", "params": {"taskId": task_id}},
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "tasks/cancel", "request": cancel_response["request"], "httpStatus": cancel_response["status"], "messages": cancel_response["messages"]})
            task_cancel = next(
                (
                    message
                    for message in cancel_response["messages"]
                    if message.get("id") == 10 and "method" not in message
                ),
                None,
            )
            if task_cancel is None:
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "tasks_cancel_terminal_response_present",
                    "tasks/cancel did not return a terminal response",
                )
            if "error" in task_cancel:
                error_message = task_cancel["error"].get("message", "tasks/cancel failed")
                return exception_result(
                    scenario,
                    error_message,
                    int((time.time() - started) * 1000),
                )
            cancel_status = task_cancel.get("result", {}).get("status")
            has_status_notification = any(
                message.get("method") == "notifications/tasks/status"
                and message.get("params", {}).get("taskId") == task_id
                for message in cancel_response["messages"]
            )
            if cancel_response["status"] != 200 or cancel_status != "cancelled" or not has_status_notification:
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "tasks_cancel_marks_cancelled_and_emits_status",
                    "tasks/cancel did not mark the task cancelled with a status notification",
                )

            result_response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {"jsonrpc": "2.0", "id": 11, "method": "tasks/result", "params": {"taskId": task_id}},
                session.session_id,
                session.protocol_version,
            )
            transcript.append({"step": "tasks/cancel-result", "request": result_response["request"], "httpStatus": result_response["status"], "messages": result_response["messages"]})
            task_result = terminal_message(result_response["messages"], 11)
            related_task_id = (
                task_result.get("result", {})
                .get("_meta", {})
                .get("io.modelcontextprotocol/related-task", {})
                .get("taskId")
            )
            if (
                result_response["status"] != 200
                or task_result.get("result", {}).get("isError") is not True
                or related_task_id != task_id
            ):
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "tasks_result_returns_cancelled_error_payload",
                    "tasks/result did not return the expected cancelled error payload",
                )

            return scenario_result(
                scenario,
                int((time.time() - started) * 1000),
                "pass",
                [
                    {"name": "task_created", "status": "pass"},
                    {"name": "tasks_cancel_marks_cancelled_and_emits_status", "status": "pass"},
                    {"name": "tasks_result_returns_cancelled_error_payload", "status": "pass"},
                ],
            )

        if scenario["id"] == "nested-sampling-create-message":
            response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {
                    "jsonrpc": "2.0",
                    "id": 50,
                    "method": "tools/call",
                    "params": {
                        "name": "sampled_echo",
                        "arguments": {"message": "nested callback sampling request"},
                    },
                },
                session.session_id,
                session.protocol_version,
                on_message=lambda message: nested_router.handle(
                    message,
                    session,
                    step_prefix="nested/sampling",
                ),
            )
            transcript.append(
                {
                    "step": "nested/sampling/tool-call",
                    "request": response["request"],
                    "httpStatus": response["status"],
                    "messages": response["messages"],
                }
            )
            terminal = terminal_message(response["messages"], 50)
            sampling_requests = [
                message
                for message in response["messages"]
                if message.get("method") == "sampling/createMessage"
            ]
            sampled_text = (
                terminal.get("result", {})
                .get("structuredContent", {})
                .get("sampled", {})
                .get("content", {})
                .get("text")
            )
            if (
                response["status"] != 200
                or len(sampling_requests) != 1
                or sampled_text != CONFORMANCE_SAMPLE_TEXT
            ):
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "nested_sampling_request_roundtrips",
                    "sampling/createMessage did not round-trip through the remote HTTP edge",
                )
            return passed_result(
                scenario,
                int((time.time() - started) * 1000),
                "nested_sampling_request_roundtrips",
            )

        if scenario["id"] == "nested-elicitation-form-create":
            response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {
                    "jsonrpc": "2.0",
                    "id": 51,
                    "method": "tools/call",
                    "params": {
                        "name": "elicited_echo",
                        "arguments": {"message": "nested callback form elicitation request"},
                    },
                },
                session.session_id,
                session.protocol_version,
                on_message=lambda message: nested_router.handle(
                    message,
                    session,
                    step_prefix="nested/elicitation-form",
                ),
            )
            transcript.append(
                {
                    "step": "nested/elicitation-form/tool-call",
                    "request": response["request"],
                    "httpStatus": response["status"],
                    "messages": response["messages"],
                }
            )
            terminal = terminal_message(response["messages"], 51)
            elicitation_requests = [
                message
                for message in response["messages"]
                if message.get("method") == "elicitation/create"
            ]
            elicited = (
                terminal.get("result", {})
                .get("structuredContent", {})
                .get("elicited", {})
            )
            if (
                response["status"] != 200
                or len(elicitation_requests) != 1
                or elicited.get("action") != "accept"
                or elicited.get("content", {}).get("answer") != CONFORMANCE_ELICITED_CONTENT["answer"]
            ):
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "nested_form_elicitation_roundtrips",
                    "form-mode elicitation/create did not round-trip through the remote HTTP edge",
                )
            return passed_result(
                scenario,
                int((time.time() - started) * 1000),
                "nested_form_elicitation_roundtrips",
            )

        if scenario["id"] == "nested-elicitation-url-create":
            response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {
                    "jsonrpc": "2.0",
                    "id": 52,
                    "method": "tools/call",
                    "params": {
                        "name": "url_elicited_echo",
                        "arguments": {"message": "nested callback url elicitation request"},
                    },
                },
                session.session_id,
                session.protocol_version,
                on_message=lambda message: nested_router.handle(
                    message,
                    session,
                    step_prefix="nested/elicitation-url",
                ),
            )
            transcript.append(
                {
                    "step": "nested/elicitation-url/tool-call",
                    "request": response["request"],
                    "httpStatus": response["status"],
                    "messages": response["messages"],
                }
            )
            terminal = terminal_message(response["messages"], 52)
            completion_notification = next(
                (
                    message
                    for message in response["messages"]
                    if message.get("method") == "notifications/elicitation/complete"
                ),
                None,
            )
            elicitation_request = next(
                (
                    message
                    for message in response["messages"]
                    if message.get("method") == "elicitation/create"
                ),
                None,
            )
            elicitation_id = (
                terminal.get("result", {})
                .get("structuredContent", {})
                .get("elicitationId")
            )
            action = (
                terminal.get("result", {})
                .get("structuredContent", {})
                .get("elicited", {})
                .get("action")
            )
            if (
                response["status"] != 200
                or elicitation_request is None
                or completion_notification is None
                or action != "accept"
                or not elicitation_id
                or completion_notification.get("params", {}).get("elicitationId") != elicitation_id
            ):
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "nested_url_elicitation_roundtrips_and_completes",
                    "URL-mode elicitation/create did not round-trip and emit completion through the remote HTTP edge",
                )
            return passed_result(
                scenario,
                int((time.time() - started) * 1000),
                "nested_url_elicitation_roundtrips_and_completes",
            )

        if scenario["id"] == "nested-roots-list":
            response = post_rpc(
                ARGS["base_url"],
                session_auth_token,
                {
                    "jsonrpc": "2.0",
                    "id": 53,
                    "method": "tools/call",
                    "params": {
                        "name": "roots_echo",
                        "arguments": {"message": "nested callback roots request"},
                    },
                },
                session.session_id,
                session.protocol_version,
                on_message=lambda message: nested_router.handle(
                    message,
                    session,
                    step_prefix="nested/roots",
                ),
            )
            transcript.append(
                {
                    "step": "nested/roots/tool-call",
                    "request": response["request"],
                    "httpStatus": response["status"],
                    "messages": response["messages"],
                }
            )
            terminal = terminal_message(response["messages"], 53)
            roots_requests = [
                message
                for message in response["messages"]
                if message.get("method") == "roots/list"
            ]
            roots = (
                terminal.get("result", {})
                .get("structuredContent", {})
                .get("roots", [])
            )
            if (
                response["status"] != 200
                or len(roots_requests) < 1
                or not roots
                or roots[0].get("uri") != CONFORMANCE_ROOTS[0]["uri"]
            ):
                return failed_result(
                    scenario,
                    int((time.time() - started) * 1000),
                    "nested_roots_list_roundtrips",
                    "roots/list did not round-trip through the remote HTTP edge",
                )
            return passed_result(
                scenario,
                int((time.time() - started) * 1000),
                "nested_roots_list_roundtrips",
            )

        result = scenario_result(scenario, int((time.time() - started) * 1000), "unsupported", [])
        result["notes"] = f"unsupported scenario id {scenario['id']}"
        return result
    except Exception as error:  # noqa: BLE001
        return exception_result(scenario, str(error), int((time.time() - started) * 1000))


scenarios = load_scenarios(Path(ARGS["scenarios_dir"]))
transcript: list[dict] = []
results: list[dict] = []
shared_session = None
auth_context = None

try:
    auth_context = resolve_auth(transcript)
    for scenario in scenarios:
        scenario_session = None
        dedicated_session = scenario_requires_dedicated_session(scenario)
        try:
            if dedicated_session:
                scenario_session = initialize_session(
                    ARGS["base_url"],
                    auth_context["access_token"],
                    transcript,
                    f"{scenario['id']}/",
                )
            else:
                if shared_session is None:
                    shared_session = initialize_session(
                        ARGS["base_url"], auth_context["access_token"], transcript
                    )
                scenario_session = shared_session
            results.append(run_scenario(scenario, auth_context, scenario_session, transcript))
        except Exception as error:  # noqa: BLE001
            results.append(exception_result(scenario, str(error)))
        finally:
            if dedicated_session and scenario_session is not None:
                try:
                    status = delete_session(scenario_session)
                    transcript.append(
                        {
                            "step": f"{scenario['id']}/delete-session",
                            "httpStatus": status,
                        }
                    )
                except Exception as error:  # noqa: BLE001
                    transcript.append(
                        {
                            "step": f"{scenario['id']}/delete-session",
                            "error": str(error),
                        }
                    )
except Exception as error:  # noqa: BLE001
    for scenario in scenarios:
        results.append(exception_result(scenario, str(error)))
finally:
    if shared_session:
        try:
            status = delete_session(shared_session)
            transcript.append({"step": "delete-session", "httpStatus": status})
        except Exception as error:  # noqa: BLE001
            transcript.append({"step": "delete-session", "error": str(error)})

artifacts_dir = Path(ARGS["artifacts_dir"])
artifacts_dir.mkdir(parents=True, exist_ok=True)
transcript_path = artifacts_dir / "transcript.jsonl"
transcript_path.write_text(
    "\n".join(json.dumps(entry) for entry in transcript) + "\n",
    encoding="utf-8",
)

for result in results:
    result["artifacts"] = {"transcript": str(transcript_path)}

results_output = Path(ARGS["results_output"])
results_output.parent.mkdir(parents=True, exist_ok=True)
results_output.write_text(f"{json.dumps(results, indent=2)}\n", encoding="utf-8")
