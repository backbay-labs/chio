#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  ChioClient,
  ChioSession,
  terminalMessage
} from "../../../../sdks/typescript/chio-ts/src/index.ts";

if (process.argv.includes("--help")) {
  console.log("Chio JS conformance client");
  process.exit(0);
}

const args = parseArgs(process.argv.slice(2));
const scenarios = loadScenarios(args.scenariosDir);
const transcript = [];
const results = [];
let sharedSession = null;
let authContext = null;

const CONFORMANCE_SAMPLE_TEXT = "sampled by conformance peer";
const CONFORMANCE_ELICITED_CONTENT = { answer: "elicited by conformance peer" };
const CONFORMANCE_ROOTS = [
  {
    uri: "file:///workspace/conformance-root",
    name: "conformance-root"
  }
];
const CONFORMANCE_CLIENT_CAPABILITIES = {
  sampling: {
    context: {},
    tools: {}
  },
  elicitation: {
    form: {},
    url: {}
  },
  roots: {
    listChanged: true
  }
};

try {
  authContext = await resolveAuth(args, transcript);
  for (const scenario of scenarios) {
    let scenarioSession = null;
    const dedicatedSession = scenarioRequiresDedicatedSession(scenario);
    try {
      if (dedicatedSession) {
        scenarioSession = await initializeSession(
          args.baseUrl,
          authContext.accessToken,
          transcript,
          `${scenario.id}/`
        );
      } else {
        if (!sharedSession) {
          sharedSession = await initializeSession(
            args.baseUrl,
            authContext.accessToken,
            transcript
          );
        }
        scenarioSession = sharedSession;
      }
      results.push(
        await runScenario(scenario, args, authContext, scenarioSession, transcript)
      );
    } catch (error) {
      results.push(failedScenarioResult(scenario, String(error)));
    } finally {
      if (dedicatedSession && scenarioSession?.sessionId) {
        await deleteSession(scenarioSession, transcript, `${scenario.id}/`);
      }
    }
  }
} catch (error) {
  for (const scenario of scenarios) {
    results.push(failedScenarioResult(scenario, String(error)));
  }
} finally {
  if (sharedSession?.sessionId) {
    await deleteSession(sharedSession, transcript);
  }
}

fs.mkdirSync(args.artifactsDir, { recursive: true });
const transcriptPath = path.join(args.artifactsDir, "transcript.jsonl");
fs.writeFileSync(
  transcriptPath,
  transcript.map((entry) => JSON.stringify(entry)).join("\n") + "\n"
);

const enriched = results.map((result) => ({
  ...result,
  artifacts: {
    ...(result.artifacts ?? {}),
    transcript: transcriptPath
  }
}));

fs.mkdirSync(path.dirname(args.resultsOutput), { recursive: true });
fs.writeFileSync(args.resultsOutput, `${JSON.stringify(enriched, null, 2)}\n`);

function parseArgs(argv) {
  const out = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag?.startsWith("--") || value === undefined) {
      throw new Error(`invalid arguments near ${flag ?? "<eof>"}`);
    }
    out[flag.slice(2).replace(/-([a-z])/g, (_, char) => char.toUpperCase())] = value;
  }
  for (const required of ["baseUrl", "authToken", "scenariosDir", "resultsOutput", "artifactsDir"]) {
    if (!out[required]) {
      throw new Error(`missing required argument --${required}`);
    }
  }
  out.authMode ??= "static-bearer";
  out.authScope ??= "mcp:invoke";
  return out;
}

function loadScenarios(root) {
  const files = collectJsonFiles(root).sort();
  return files.map((file) => JSON.parse(fs.readFileSync(file, "utf8")));
}

function scenarioRequiresDedicatedSession(scenario) {
  return scenario.id.startsWith("nested-");
}

function collectJsonFiles(root) {
  const entries = [];
  for (const item of fs.readdirSync(root, { withFileTypes: true })) {
    const resolved = path.join(root, item.name);
    if (item.isDirectory()) {
      entries.push(...collectJsonFiles(resolved));
    } else if (item.isFile() && item.name.endsWith(".json")) {
      entries.push(resolved);
    }
  }
  return entries;
}

async function resolveAuth(args, transcript) {
  if (args.authMode !== "oauth-local") {
    return {
      mode: "static-bearer",
      accessToken: args.authToken
    };
  }

  const protectedResourceResponse = await fetchJson(`${args.baseUrl}/.well-known/oauth-protected-resource/mcp`);
  transcript.push({
    step: "auth/protected-resource-metadata",
    httpStatus: protectedResourceResponse.status,
    headers: protectedResourceResponse.headers,
    body: protectedResourceResponse.body
  });
  const protectedResourceMetadata = protectedResourceResponse.body;
  const issuer = protectedResourceMetadata.authorization_servers?.[0];
  if (!issuer) {
    throw new Error("protected resource metadata did not advertise an authorization server");
  }

  const authorizationServerResponse = await fetchJson(
    authorizationServerMetadataUrl(args.baseUrl, issuer)
  );
  transcript.push({
    step: "auth/authorization-server-metadata",
    httpStatus: authorizationServerResponse.status,
    headers: authorizationServerResponse.headers,
    body: authorizationServerResponse.body
  });

  const authorizationServerMetadata = authorizationServerResponse.body;
  const accessToken = await performAuthorizationCodeFlow(
    args.baseUrl,
    args.authScope,
    authorizationServerMetadata,
    transcript
  );

  return {
    mode: "oauth-local",
    accessToken,
    protectedResourceMetadata,
    authorizationServerMetadata
  };
}

async function initializeSession(baseUrl, authToken, transcript, stepPrefix = "") {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const client = ChioClient.withStaticBearer(baseUrl, authToken);
      const session = await client.initialize({
        capabilities: CONFORMANCE_CLIENT_CAPABILITIES,
        clientInfo: {
          name: "chio-conformance-js",
          version: "0.1.0"
        },
        onMessage: async (message, session) => {
          await handleNestedClientRequest(
            message,
            baseUrl,
            authToken,
            session,
            transcript,
            `${stepPrefix}notifications/initialized/nested`
          );
        }
      });
      transcript.push({
        step: `${stepPrefix}initialize`,
        request: session.handshake?.initializeResponse.request,
        httpStatus: session.handshake?.initializeResponse.status,
        headers: session.handshake?.initializeResponse.headers,
        messages: session.handshake?.initializeResponse.messages
      });
      transcript.push({
        step: `${stepPrefix}notifications/initialized`,
        request: session.handshake?.initializedResponse.request,
        httpStatus: session.handshake?.initializedResponse.status,
        messages: session.handshake?.initializedResponse.messages
      });
      return session;
    } catch (error) {
      if (attempt === 29) {
        throw error;
      }
      await sleep(100);
    }
  }
  throw new Error("unreachable initialize retry path");
}

async function deleteSession(session, transcript, stepPrefix = "") {
  const response = await session.close();
  transcript.push({ step: `${stepPrefix}delete-session`, httpStatus: response.status });
}

async function postRpc(
  baseUrl,
  authToken,
  sessionId,
  protocolVersion,
  body,
  onMessage = async () => {}
) {
  const session = new ChioSession({
    baseUrl,
    authToken,
    sessionId,
    protocolVersion
  });
  return session.sendEnvelope(body, onMessage);
}

async function postNotification(
  baseUrl,
  authToken,
  sessionId,
  protocolVersion,
  body,
  onMessage = async () => {}
) {
  const session = new ChioSession({
    baseUrl,
    authToken,
    sessionId,
    protocolVersion
  });
  return session.sendEnvelope(body, onMessage);
}

async function runScenario(scenario, args, authContext, session, transcript) {
  const startedAt = Date.now();
  const sessionAuthToken = authContext.accessToken;
  try {
    switch (scenario.id) {
      case "initialize":
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "initialize_succeeds", status: "pass" }]
        );
      case "tools-list": {
        const response = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }
        );
        transcript.push({ step: "tools/list", request: response.request, httpStatus: response.status, messages: response.messages });
        const message = terminalMessage(response.messages, 2);
        const tools = message.result?.tools;
        const found = Array.isArray(tools) && tools.some((tool) => tool.name === "echo_text");
        if (response.status !== 200 || !found) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "tools_list_contains_echo_text",
            "tools/list did not return the expected echo_text fixture"
          );
        }
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "tools_list_contains_echo_text", status: "pass" }]
        );
      }
      case "tools-call-simple-text": {
        const requestBody = {
          jsonrpc: "2.0",
          id: 3,
          method: "tools/call",
          params: {
            name: "echo_text",
            arguments: {
              message: "hello from js peer"
            }
          }
        };
        const response = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          requestBody
        );
        transcript.push({ step: "tools/call", request: response.request, httpStatus: response.status, messages: response.messages });
        const message = terminalMessage(response.messages, 3);
        const text = message.result?.content?.[0]?.text;
        if (response.status !== 200 || text !== "hello from js peer") {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "tool_result_matches_input_text",
            `unexpected tool text result: ${text ?? "<missing>"}`
          );
        }
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "tool_result_matches_input_text", status: "pass" }]
        );
      }
      case "resources-list": {
        const response = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          { jsonrpc: "2.0", id: 4, method: "resources/list", params: {} }
        );
        transcript.push({ step: "resources/list", request: response.request, httpStatus: response.status, messages: response.messages });
        const message = terminalMessage(response.messages, 4);
        const resources = message.result?.resources;
        const found = Array.isArray(resources) && resources.some((resource) => resource.uri === "fixture://docs/alpha");
        if (response.status !== 200 || !found) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "resources_list_contains_fixture_uri",
            "resources/list did not include fixture://docs/alpha"
          );
        }
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "resources_list_contains_fixture_uri", status: "pass" }]
        );
      }
      case "prompts-list": {
        const response = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          { jsonrpc: "2.0", id: 5, method: "prompts/list", params: {} }
        );
        transcript.push({ step: "prompts/list", request: response.request, httpStatus: response.status, messages: response.messages });
        const message = terminalMessage(response.messages, 5);
        const prompts = message.result?.prompts;
        const found = Array.isArray(prompts) && prompts.some((prompt) => prompt.name === "summarize_fixture");
        if (response.status !== 200 || !found) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "prompts_list_contains_fixture_prompt",
            "prompts/list did not include summarize_fixture"
          );
        }
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "prompts_list_contains_fixture_prompt", status: "pass" }]
        );
      }
      case "tasks-call-get-result": {
        const create = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 6,
            method: "tools/call",
            params: {
              name: "echo_text",
              arguments: {
                message: "hello from js task peer"
              },
              task: {}
            }
          }
        );
        transcript.push({ step: "tasks/tools-call", request: create.request, httpStatus: create.status, messages: create.messages });
        const createMessage = terminalMessage(create.messages, 6);
        const taskId = createMessage.result?.task?.taskId;
        if (create.status !== 200 || !taskId) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "task_created",
            "task-augmented tools/call did not return a task id"
          );
        }

        const getResponse = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 7,
            method: "tasks/get",
            params: { taskId }
          }
        );
        transcript.push({ step: "tasks/get", request: getResponse.request, httpStatus: getResponse.status, messages: getResponse.messages });
        const taskGet = terminalMessage(getResponse.messages, 7);
        const getStatus = taskGet.result?.status;
        if (getResponse.status !== 200 || !["working", "completed"].includes(getStatus)) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "tasks_get_returns_working_or_completed",
            `unexpected tasks/get status: ${getStatus ?? "<missing>"}`
          );
        }

        const resultResponse = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 8,
            method: "tasks/result",
            params: { taskId }
          }
        );
        transcript.push({ step: "tasks/result", request: resultResponse.request, httpStatus: resultResponse.status, messages: resultResponse.messages });
        const taskResult = terminalMessage(resultResponse.messages, 8);
        const relatedTaskId =
          taskResult.result?._meta?.["io.modelcontextprotocol/related-task"]?.taskId;
        const text = taskResult.result?.content?.[0]?.text;
        if (
          resultResponse.status !== 200 ||
          relatedTaskId !== taskId ||
          text !== "hello from js task peer"
        ) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "tasks_result_returns_related_terminal_payload",
            "tasks/result did not return the expected related-task metadata or payload"
          );
        }

        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [
            { name: "task_created", status: "pass" },
            { name: "tasks_get_returns_working_or_completed", status: "pass" },
            { name: "tasks_result_returns_related_terminal_payload", status: "pass" }
          ]
        );
      }
      case "tasks-cancel": {
        const create = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 9,
            method: "tools/call",
            params: {
              name: "slow_echo",
              arguments: {
                message: "hello from js cancel peer"
              },
              task: {}
            }
          }
        );
        transcript.push({ step: "tasks/cancel-create", request: create.request, httpStatus: create.status, messages: create.messages });
        const createMessage = terminalMessage(create.messages, 9);
        const taskId = createMessage.result?.task?.taskId;
        if (create.status !== 200 || !taskId) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "task_created",
            "task-augmented slow tools/call did not return a task id"
          );
        }

        const cancelResponse = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 10,
            method: "tasks/cancel",
            params: { taskId }
          }
        );
        transcript.push({ step: "tasks/cancel", request: cancelResponse.request, httpStatus: cancelResponse.status, messages: cancelResponse.messages });
        const taskCancel = cancelResponse.messages.find((message) => message.id === 10 && !message.method);
        if (!taskCancel) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "tasks_cancel_terminal_response_present",
            "tasks/cancel did not return a terminal response"
          );
        }
        if (taskCancel.error) {
          return failedScenarioResult(
            scenario,
            `Error: ${taskCancel.error.message ?? "tasks/cancel failed"}`,
            Date.now() - startedAt
          );
        }
        const cancelStatus = taskCancel.result?.status;
        const hasStatusNotification = cancelResponse.messages.some(
          (message) =>
            message.method === "notifications/tasks/status" &&
            message.params?.taskId === taskId
        );
        if (cancelResponse.status !== 200 || cancelStatus !== "cancelled" || !hasStatusNotification) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "tasks_cancel_marks_cancelled_and_emits_status",
            "tasks/cancel did not mark the task cancelled with a status notification"
          );
        }

        const resultResponse = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 11,
            method: "tasks/result",
            params: { taskId }
          }
        );
        transcript.push({ step: "tasks/cancel-result", request: resultResponse.request, httpStatus: resultResponse.status, messages: resultResponse.messages });
        const taskResult = terminalMessage(resultResponse.messages, 11);
        const relatedTaskId =
          taskResult.result?._meta?.["io.modelcontextprotocol/related-task"]?.taskId;
        if (resultResponse.status !== 200 || taskResult.result?.isError !== true || relatedTaskId !== taskId) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "tasks_result_returns_cancelled_error_payload",
            "tasks/result did not return the expected cancelled error payload"
          );
        }

        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [
            { name: "task_created", status: "pass" },
            { name: "tasks_cancel_marks_cancelled_and_emits_status", status: "pass" },
            { name: "tasks_result_returns_cancelled_error_payload", status: "pass" }
          ]
        );
      }
      case "auth-unauthorized-challenge": {
        const response = await fetch(`${args.baseUrl}/mcp`, {
          method: "POST",
          headers: {
            Accept: "application/json, text/event-stream",
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 20,
            method: "initialize",
            params: {
              protocolVersion: "2025-11-25",
              capabilities: {},
              clientInfo: { name: "chio-conformance-js-unauthorized", version: "0.1.0" }
            }
          })
        });
        const body = await response.text();
        transcript.push({
          step: "auth/unauthorized-challenge",
          httpStatus: response.status,
          headers: Object.fromEntries(response.headers.entries()),
          body
        });
        const challenge = response.headers.get("www-authenticate") ?? "";
        if (response.status !== 401 || !challenge.includes("resource_metadata=")) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "unauthorized_initialize_returns_resource_metadata_challenge",
            "unauthorized initialize did not return a protected-resource challenge"
          );
        }
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "unauthorized_initialize_returns_resource_metadata_challenge", status: "pass" }]
        );
      }
      case "auth-protected-resource-metadata": {
        const servers = authContext.protectedResourceMetadata?.authorization_servers;
        const scopes = authContext.protectedResourceMetadata?.scopes_supported;
        const ok =
          Array.isArray(servers) &&
          servers.length > 0 &&
          Array.isArray(scopes) &&
          scopes.includes(args.authScope);
        if (!ok) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "protected_resource_metadata_advertises_auth_server_and_scope",
            "protected resource metadata did not advertise the expected auth server and scope"
          );
        }
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "protected_resource_metadata_advertises_auth_server_and_scope", status: "pass" }]
        );
      }
      case "auth-authorization-server-metadata": {
        const grants = authContext.authorizationServerMetadata?.grant_types_supported;
        const ok =
          Array.isArray(grants) &&
          grants.includes("authorization_code") &&
          grants.includes("urn:ietf:params:oauth:grant-type:token-exchange") &&
          typeof authContext.authorizationServerMetadata?.authorization_endpoint === "string" &&
          typeof authContext.authorizationServerMetadata?.token_endpoint === "string";
        if (!ok) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "authorization_server_metadata_advertises_expected_grants",
            "authorization server metadata did not advertise the expected grant types and endpoints"
          );
        }
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "authorization_server_metadata_advertises_expected_grants", status: "pass" }]
        );
      }
      case "auth-code-initialize": {
        const extraSession = await initializeSession(
          args.baseUrl,
          authContext.accessToken,
          transcript,
          "auth-code/"
        );
        await deleteSession(extraSession, transcript, "auth-code/");
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "authorization_code_access_token_initializes_session", status: "pass" }]
        );
      }
      case "auth-token-exchange-initialize": {
        const exchangedToken = await exchangeAccessToken(
          args.baseUrl,
          args.authScope,
          authContext,
          transcript
        );
        const exchangedSession = await initializeSession(
          args.baseUrl,
          exchangedToken,
          transcript,
          "token-exchange/"
        );
        await deleteSession(exchangedSession, transcript, "token-exchange/");
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "token_exchange_access_token_initializes_session", status: "pass" }]
        );
      }
      case "resources-subscribe-updated-notification": {
        const subscribedUri = "fixture://docs/alpha";
        const subscribeResponse = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 40,
            method: "resources/subscribe",
            params: { uri: subscribedUri }
          }
        );
        transcript.push({
          step: "resources/subscribe",
          request: subscribeResponse.request,
          httpStatus: subscribeResponse.status,
          messages: subscribeResponse.messages
        });
        terminalMessage(subscribeResponse.messages, 40);
        if (subscribeResponse.status !== 200) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "resources_subscribe_succeeds",
            "resources/subscribe did not succeed"
          );
        }

        const triggerResponse = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 41,
            method: "tools/call",
            params: {
              name: "emit_fixture_notifications",
              arguments: { uri: subscribedUri }
            }
          }
        );
        transcript.push({
          step: "notifications/trigger-updated",
          request: triggerResponse.request,
          httpStatus: triggerResponse.status,
          messages: triggerResponse.messages
        });
        terminalMessage(triggerResponse.messages, 41);
        const updateDelivered = triggerResponse.messages.some(
          (message) =>
            message.method === "notifications/resources/updated" &&
            message.params?.uri === subscribedUri
        );
        if (triggerResponse.status !== 200 || !updateDelivered) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "subscribed_resource_update_is_forwarded",
            "wrapped notification flow did not deliver notifications/resources/updated for the subscribed URI"
          );
        }

        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [
            { name: "resources_subscribe_succeeds", status: "pass" },
            { name: "subscribed_resource_update_is_forwarded", status: "pass" }
          ]
        );
      }
      case "catalog-list-changed-notifications": {
        const triggerResponse = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 42,
            method: "tools/call",
            params: {
              name: "emit_fixture_notifications",
              arguments: { uri: "fixture://docs/alpha" }
            }
          }
        );
        transcript.push({
          step: "notifications/trigger-catalog",
          request: triggerResponse.request,
          httpStatus: triggerResponse.status,
          messages: triggerResponse.messages
        });
        terminalMessage(triggerResponse.messages, 42);
        const methods = new Set(
          triggerResponse.messages.map((message) => message.method).filter(Boolean)
        );
        const hasAll =
          methods.has("notifications/resources/list_changed") &&
          methods.has("notifications/tools/list_changed") &&
          methods.has("notifications/prompts/list_changed");
        if (triggerResponse.status !== 200 || !hasAll) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "catalog_list_changed_notifications_are_forwarded",
            "wrapped notification flow did not deliver the expected list-changed notifications"
          );
        }

        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "catalog_list_changed_notifications_are_forwarded", status: "pass" }]
        );
      }
      case "nested-sampling-create-message": {
        const response = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 50,
            method: "tools/call",
            params: {
              name: "sampled_echo",
              arguments: {
                message: "nested callback sampling request"
              }
            }
          },
          async (message) => {
            await handleNestedClientRequest(
              message,
              args.baseUrl,
              sessionAuthToken,
              session,
              transcript,
              "nested/sampling"
            );
          }
        );
        transcript.push({
          step: "nested/sampling/tool-call",
          request: response.request,
          httpStatus: response.status,
          messages: response.messages
        });
        const terminal = terminalMessage(response.messages, 50);
        const samplingRequests = response.messages.filter(
          (message) => message.method === "sampling/createMessage"
        );
        const sampledText = terminal.result?.structuredContent?.sampled?.content?.text;
        if (
          response.status !== 200 ||
          samplingRequests.length !== 1 ||
          sampledText !== CONFORMANCE_SAMPLE_TEXT
        ) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "nested_sampling_request_roundtrips",
            "sampling/createMessage did not round-trip through the remote HTTP edge"
          );
        }
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "nested_sampling_request_roundtrips", status: "pass" }]
        );
      }
      case "nested-elicitation-form-create": {
        const response = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 51,
            method: "tools/call",
            params: {
              name: "elicited_echo",
              arguments: {
                message: "nested callback form elicitation request"
              }
            }
          },
          async (message) => {
            await handleNestedClientRequest(
              message,
              args.baseUrl,
              sessionAuthToken,
              session,
              transcript,
              "nested/elicitation-form"
            );
          }
        );
        transcript.push({
          step: "nested/elicitation-form/tool-call",
          request: response.request,
          httpStatus: response.status,
          messages: response.messages
        });
        const terminal = terminalMessage(response.messages, 51);
        const elicitationRequests = response.messages.filter(
          (message) => message.method === "elicitation/create"
        );
        const action = terminal.result?.structuredContent?.elicited?.action;
        const answer = terminal.result?.structuredContent?.elicited?.content?.answer;
        if (
          response.status !== 200 ||
          elicitationRequests.length !== 1 ||
          action !== "accept" ||
          answer !== CONFORMANCE_ELICITED_CONTENT.answer
        ) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "nested_form_elicitation_roundtrips",
            "form-mode elicitation/create did not round-trip through the remote HTTP edge"
          );
        }
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "nested_form_elicitation_roundtrips", status: "pass" }]
        );
      }
      case "nested-elicitation-url-create": {
        const response = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 52,
            method: "tools/call",
            params: {
              name: "url_elicited_echo",
              arguments: {
                message: "nested callback url elicitation request"
              }
            }
          },
          async (message) => {
            await handleNestedClientRequest(
              message,
              args.baseUrl,
              sessionAuthToken,
              session,
              transcript,
              "nested/elicitation-url"
            );
          }
        );
        transcript.push({
          step: "nested/elicitation-url/tool-call",
          request: response.request,
          httpStatus: response.status,
          messages: response.messages
        });
        const terminal = terminalMessage(response.messages, 52);
        const elicitationRequest = response.messages.find(
          (message) => message.method === "elicitation/create"
        );
        const completionNotification = response.messages.find(
          (message) => message.method === "notifications/elicitation/complete"
        );
        const elicitationId = terminal.result?.structuredContent?.elicitationId;
        const action = terminal.result?.structuredContent?.elicited?.action;
        const completionId = completionNotification?.params?.elicitationId;
        if (
          response.status !== 200 ||
          !elicitationRequest ||
          !completionNotification ||
          action !== "accept" ||
          !elicitationId ||
          completionId !== elicitationId
        ) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "nested_url_elicitation_roundtrips_and_completes",
            "URL-mode elicitation/create did not round-trip and emit completion through the remote HTTP edge"
          );
        }
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "nested_url_elicitation_roundtrips_and_completes", status: "pass" }]
        );
      }
      case "nested-roots-list": {
        const response = await postRpc(
          args.baseUrl,
          sessionAuthToken,
          session.sessionId,
          session.protocolVersion,
          {
            jsonrpc: "2.0",
            id: 53,
            method: "tools/call",
            params: {
              name: "roots_echo",
              arguments: {
                message: "nested callback roots request"
              }
            }
          },
          async (message) => {
            await handleNestedClientRequest(
              message,
              args.baseUrl,
              sessionAuthToken,
              session,
              transcript,
              "nested/roots"
            );
          }
        );
        transcript.push({
          step: "nested/roots/tool-call",
          request: response.request,
          httpStatus: response.status,
          messages: response.messages
        });
        const terminal = terminalMessage(response.messages, 53);
        const rootsRequests = response.messages.filter(
          (message) => message.method === "roots/list"
        );
        const roots = terminal.result?.structuredContent?.roots;
        const firstRootUri = roots?.[0]?.uri;
        if (
          response.status !== 200 ||
          rootsRequests.length < 1 ||
          firstRootUri !== CONFORMANCE_ROOTS[0].uri
        ) {
          return failedAssertionResult(
            scenario,
            Date.now() - startedAt,
            "nested_roots_list_roundtrips",
            "roots/list did not round-trip through the remote HTTP edge"
          );
        }
        return passedScenarioResult(
          scenario,
          Date.now() - startedAt,
          [{ name: "nested_roots_list_roundtrips", status: "pass" }]
        );
      }
      default:
        return unsupportedScenarioResult(scenario, Date.now() - startedAt, `unsupported scenario id ${scenario.id}`);
    }
  } catch (error) {
    return failedScenarioResult(scenario, String(error), Date.now() - startedAt);
  }
}

async function handleNestedClientRequest(
  message,
  baseUrl,
  authToken,
  session,
  transcript,
  stepPrefix
) {
  switch (message.method) {
    case "sampling/createMessage": {
      const followUp = await postNotification(
        baseUrl,
        authToken,
        session.sessionId,
        session.protocolVersion,
        {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            role: "assistant",
            content: {
              type: "text",
              text: CONFORMANCE_SAMPLE_TEXT
            },
            model: "chio-conformance-js-model",
            stopReason: "end_turn"
          }
        }
      );
      transcript.push({
        step: `${stepPrefix}/sampling-response`,
        request: followUp.request,
        httpStatus: followUp.status,
        messages: followUp.messages
      });
      return;
    }
    case "elicitation/create": {
      const mode = message.params?.mode;
      const result =
        mode === "url"
          ? { action: "accept" }
          : { action: "accept", content: CONFORMANCE_ELICITED_CONTENT };
      const followUp = await postNotification(
        baseUrl,
        authToken,
        session.sessionId,
        session.protocolVersion,
        {
          jsonrpc: "2.0",
          id: message.id,
          result
        }
      );
      transcript.push({
        step: `${stepPrefix}/elicitation-response`,
        request: followUp.request,
        httpStatus: followUp.status,
        messages: followUp.messages
      });
      return;
    }
    case "roots/list": {
      const followUp = await postNotification(
        baseUrl,
        authToken,
        session.sessionId,
        session.protocolVersion,
        {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            roots: CONFORMANCE_ROOTS
          }
        }
      );
      transcript.push({
        step: `${stepPrefix}/roots-response`,
        request: followUp.request,
        httpStatus: followUp.status,
        messages: followUp.messages
      });
      return;
    }
    default:
      return;
  }
}

function authorizationServerMetadataUrl(baseUrl, issuer) {
  const issuerUrl = new URL(issuer);
  const issuerPath = issuerUrl.pathname.replace(/^\/+|\/+$/g, "");
  return issuerPath
    ? `${baseUrl}/.well-known/oauth-authorization-server/${issuerPath}`
    : `${baseUrl}/.well-known/oauth-authorization-server`;
}

function pkceChallenge(verifier) {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

async function fetchJson(url) {
  const response = await fetch(url);
  const headers = Object.fromEntries(response.headers.entries());
  const body = await response.json();
  return { status: response.status, headers, body };
}

async function performAuthorizationCodeFlow(baseUrl, authScope, authorizationServerMetadata, transcript) {
  const codeVerifier = "chio-conformance-js-verifier";
  const redirectUri = "http://localhost:7777/callback";
  const resource = `${baseUrl}/mcp`;
  const state = "chio-js-state";
  const authorizationEndpoint =
    authorizationServerMetadata.authorization_endpoint ?? `${baseUrl}/oauth/authorize`;
  const tokenEndpoint = authorizationServerMetadata.token_endpoint ?? `${baseUrl}/oauth/token`;
  const clientId = "https://client.example/app";
  const challenge = pkceChallenge(codeVerifier);

  const authorizeUrl = new URL(authorizationEndpoint);
  authorizeUrl.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    resource,
    scope: authScope,
    code_challenge: challenge,
    code_challenge_method: "S256"
  }).toString();
  const authorizeResponse = await fetch(authorizeUrl, { redirect: "manual" });
  const authorizePage = await authorizeResponse.text();
  transcript.push({
    step: "auth/authorize-page",
    httpStatus: authorizeResponse.status,
    headers: Object.fromEntries(authorizeResponse.headers.entries()),
    body: authorizePage
  });
  if (authorizeResponse.status !== 200 || !authorizePage.includes("Approve")) {
    throw new Error("authorization endpoint did not return an approval page");
  }

  const approvalBody = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    resource,
    scope: authScope,
    code_challenge: challenge,
    code_challenge_method: "S256",
    decision: "approve"
  }).toString();
  const approvalResponse = await fetch(authorizationEndpoint, {
    method: "POST",
    redirect: "manual",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: approvalBody
  });
  transcript.push({
    step: "auth/authorize-approve",
    httpStatus: approvalResponse.status,
    headers: Object.fromEntries(approvalResponse.headers.entries())
  });
  if (approvalResponse.status < 300 || approvalResponse.status >= 400) {
    throw new Error("authorization approval did not redirect with a code");
  }
  const location = approvalResponse.headers.get("location");
  if (!location) {
    throw new Error("authorization approval did not provide a redirect location");
  }
  const code = new URL(location).searchParams.get("code");
  if (!code) {
    throw new Error("authorization approval redirect did not include a code");
  }

  const tokenResponse = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: codeVerifier,
      resource
    }).toString()
  });
  const tokenBody = await tokenResponse.json();
  transcript.push({
    step: "auth/token",
    httpStatus: tokenResponse.status,
    headers: Object.fromEntries(tokenResponse.headers.entries()),
    body: tokenBody
  });
  if (tokenResponse.status !== 200 || typeof tokenBody.access_token !== "string") {
    throw new Error("authorization code exchange did not return an access token");
  }
  return tokenBody.access_token;
}

async function exchangeAccessToken(baseUrl, authScope, authContext, transcript) {
  const tokenEndpoint =
    authContext.authorizationServerMetadata?.token_endpoint ?? `${baseUrl}/oauth/token`;
  const response = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: authContext.accessToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      resource: `${baseUrl}/mcp`,
      scope: authScope
    }).toString()
  });
  const body = await response.json();
  transcript.push({
    step: "auth/token-exchange",
    httpStatus: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body
  });
  if (response.status !== 200 || typeof body.access_token !== "string") {
    throw new Error("token exchange did not return an access token");
  }
  return body.access_token;
}

function passedScenarioResult(scenario, durationMs, assertions) {
  return scenarioResult(scenario, durationMs, "pass", assertions);
}

function unsupportedScenarioResult(scenario, durationMs, notes) {
  return {
    ...scenarioResult(scenario, durationMs, "unsupported", []),
    notes
  };
}

function failedAssertionResult(scenario, durationMs, name, message) {
  return {
    ...scenarioResult(scenario, durationMs, "fail", [
      { name, status: "fail", message }
    ]),
    failureKind: "assertion-failed",
    failureMessage: message
  };
}

function failedScenarioResult(scenario, error, durationMs = 0) {
  return {
    ...scenarioResult(scenario, durationMs, "fail", [
      { name: "scenario_execution", status: "fail", message: error }
    ]),
    failureKind: "exception",
    failureMessage: error
  };
}

function xfailedScenarioResult(scenario, durationMs, assertionName, message) {
  return {
    ...scenarioResult(scenario, durationMs, "xfail", [
      { name: assertionName, status: "fail", message }
    ]),
    notes: scenario.notes ?? message,
    failureKind: "expected-failure",
    failureMessage: message,
    expectedFailure: true
  };
}

function scenarioResult(scenario, durationMs, status, assertions) {
  return {
    scenarioId: scenario.id,
    peer: "js",
    peerRole: "client_to_chio_server",
    deploymentMode: "remote_http",
    transport: "streamable-http",
    specVersion: scenario.specVersions?.[0] ?? "2025-11-25",
    category: scenario.category,
    status,
    durationMs,
    assertions,
    expectedFailure: status === "xfail"
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
