package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/backbay-labs/chio/sdks/go/chio-go/auth"
	"github.com/backbay-labs/chio/sdks/go/chio-go/client"
	"github.com/backbay-labs/chio/sdks/go/chio-go/nested"
	"github.com/backbay-labs/chio/sdks/go/chio-go/session"
	"github.com/backbay-labs/chio/sdks/go/chio-go/transport"
	"github.com/backbay-labs/chio/sdks/go/chio-go/version"
)

type scenario struct {
	ID           string   `json:"id"`
	Category     string   `json:"category"`
	SpecVersions []string `json:"specVersions"`
}

type authContext struct {
	Mode                        string
	AccessToken                 string
	AuthorizationServerMetadata map[string]any
	ProtectedResourceMetadata   map[string]any
}

var (
	conformanceSampleText      = "sampled by conformance peer"
	conformanceElicitedContent = map[string]any{
		"answer": "elicited by conformance peer",
	}
	conformanceRoots = []map[string]any{
		{
			"uri":  "file:///workspace/conformance-root",
			"name": "conformance-root",
		},
	}
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	args, err := parseArgs()
	if err != nil {
		return err
	}
	if args.authMode != "static-bearer" && args.authMode != "oauth-local" {
		return fmt.Errorf("go conformance peer supports only --auth-mode static-bearer or oauth-local")
	}

	scenarios, err := loadScenarios(args.scenariosDir)
	if err != nil {
		return err
	}

	transcript := make([]map[string]any, 0)
	results := make([]map[string]any, 0, len(scenarios))
	ctx := context.Background()
	authContext, err := resolveAuth(ctx, args, &transcript)
	if err != nil {
		for _, descriptor := range scenarios {
			results = append(results, exceptionResult(descriptor, err.Error(), 0))
		}
		return writeOutputs(args.resultsOutput, args.artifactsDir, transcript, results)
	}
	chioClient := client.WithStaticBearer(args.baseURL, args.authToken, nil)
	if authContext.AccessToken != "" {
		chioClient = client.WithStaticBearer(args.baseURL, authContext.AccessToken, nil)
	}
	var sharedSession *session.Session

	for _, descriptor := range scenarios {
		dedicatedSession := scenarioRequiresDedicatedSession(descriptor)
		scenarioSession := sharedSession

		if dedicatedSession {
			scenarioSession, err = initializeSession(
				ctx,
				chioClient,
				&transcript,
				descriptor.ID+"/",
				conformanceClientCapabilities(),
			)
			if err != nil {
				results = append(results, exceptionResult(descriptor, err.Error(), 0))
				continue
			}
		} else if sharedSession == nil {
			sharedSession, err = initializeSession(ctx, chioClient, &transcript, "", nil)
			if err != nil {
				results = append(results, exceptionResult(descriptor, err.Error(), 0))
				continue
			}
			scenarioSession = sharedSession
		}

		results = append(results, runScenario(ctx, descriptor, args, authContext, scenarioSession, &transcript))
		if dedicatedSession {
			closeSession(ctx, scenarioSession, &transcript, descriptor.ID+"/")
		}
	}

	if sharedSession != nil {
		closeSession(ctx, sharedSession, &transcript, "")
	}

	return writeOutputs(args.resultsOutput, args.artifactsDir, transcript, results)
}

type cliArgs struct {
	adminToken    string
	authMode      string
	authScope     string
	authToken     string
	artifactsDir  string
	baseURL       string
	resultsOutput string
	scenariosDir  string
}

func parseArgs() (cliArgs, error) {
	var args cliArgs
	flag.StringVar(&args.baseURL, "base-url", "", "")
	flag.StringVar(&args.authMode, "auth-mode", "static-bearer", "")
	flag.StringVar(&args.authToken, "auth-token", "", "")
	flag.StringVar(&args.adminToken, "admin-token", "", "")
	flag.StringVar(&args.authScope, "auth-scope", "mcp:invoke", "")
	flag.StringVar(&args.scenariosDir, "scenarios-dir", "", "")
	flag.StringVar(&args.resultsOutput, "results-output", "", "")
	flag.StringVar(&args.artifactsDir, "artifacts-dir", "", "")
	flag.Parse()

	if args.authToken == "" {
		args.authToken = strings.TrimSpace(os.Getenv("CHIO_CONFORMANCE_AUTH_TOKEN"))
	}
	if args.adminToken == "" {
		args.adminToken = strings.TrimSpace(os.Getenv("CHIO_CONFORMANCE_ADMIN_TOKEN"))
	}

	switch {
	case args.baseURL == "":
		return args, fmt.Errorf("missing required argument --base-url")
	case args.authToken == "":
		return args, fmt.Errorf("missing required argument --auth-token (or CHIO_CONFORMANCE_AUTH_TOKEN)")
	case args.scenariosDir == "":
		return args, fmt.Errorf("missing required argument --scenarios-dir")
	case args.resultsOutput == "":
		return args, fmt.Errorf("missing required argument --results-output")
	case args.artifactsDir == "":
		return args, fmt.Errorf("missing required argument --artifacts-dir")
	default:
		return args, nil
	}
}

func loadScenarios(root string) ([]scenario, error) {
	paths := make([]string, 0)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && filepath.Ext(path) == ".json" {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(paths)

	scenarios := make([]scenario, 0, len(paths))
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var descriptor scenario
		if err := json.Unmarshal(body, &descriptor); err != nil {
			return nil, err
		}
		scenarios = append(scenarios, descriptor)
	}
	return scenarios, nil
}

func runScenario(
	ctx context.Context,
	descriptor scenario,
	args cliArgs,
	authContext authContext,
	chioSession *session.Session,
	transcript *[]map[string]any,
) map[string]any {
	started := time.Now()
	nestedRouter := buildNestedCallbackRouter(transcript)
	switch descriptor.ID {
	case "initialize":
		return passedResult(descriptor, time.Since(started), "initialize_succeeds")
	case "tools-list":
		exchange, terminal, err := requestResult(ctx, chioSession, "tools/list", map[string]any{}, "tools/list")
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, exchange)
		tools, _ := terminal["tools"].([]any)
		for _, entry := range tools {
			tool, _ := entry.(map[string]any)
			if tool["name"] == "echo_text" {
				return passedResult(descriptor, time.Since(started), "tools_list_contains_echo_text")
			}
		}
		return failedResult(descriptor, time.Since(started), "tools_list_contains_echo_text", "tools/list did not include echo_text")
	case "tools-call-simple-text":
		exchange, terminal, err := requestResult(ctx, chioSession, "tools/call", map[string]any{
			"name":      "echo_text",
			"arguments": map[string]any{"message": "hello from go peer"},
		}, "tools/call")
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, exchange)
		content, _ := terminal["content"].([]any)
		if len(content) > 0 {
			first, _ := content[0].(map[string]any)
			if first["text"] == "hello from go peer" {
				return passedResult(descriptor, time.Since(started), "tool_result_matches_input_text")
			}
		}
		return failedResult(descriptor, time.Since(started), "tool_result_matches_input_text", "unexpected tool text result")
	case "resources-list":
		exchange, terminal, err := requestResult(ctx, chioSession, "resources/list", map[string]any{}, "resources/list")
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, exchange)
		resources, _ := terminal["resources"].([]any)
		for _, entry := range resources {
			resource, _ := entry.(map[string]any)
			if resource["uri"] == "fixture://docs/alpha" {
				return passedResult(descriptor, time.Since(started), "resources_list_contains_fixture_uri")
			}
		}
		return failedResult(descriptor, time.Since(started), "resources_list_contains_fixture_uri", "resources/list did not include fixture://docs/alpha")
	case "prompts-list":
		exchange, terminal, err := requestResult(ctx, chioSession, "prompts/list", map[string]any{}, "prompts/list")
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, exchange)
		prompts, _ := terminal["prompts"].([]any)
		for _, entry := range prompts {
			prompt, _ := entry.(map[string]any)
			if prompt["name"] == "summarize_fixture" {
				return passedResult(descriptor, time.Since(started), "prompts_list_contains_fixture_prompt")
			}
		}
		return failedResult(descriptor, time.Since(started), "prompts_list_contains_fixture_prompt", "prompts/list did not include summarize_fixture")
	case "auth-unauthorized-challenge":
		requestBody := map[string]any{
			"jsonrpc": "2.0",
			"id":      20,
			"method":  "initialize",
			"params": map[string]any{
				"protocolVersion": "2025-11-25",
				"capabilities":    map[string]any{},
				"clientInfo": map[string]any{
					"name":    "chio-conformance-go-unauthorized",
					"version": version.ModuleVersion,
				},
			},
		}
		requestPayload, err := json.Marshal(requestBody)
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		request, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			strings.TrimRight(args.baseURL, "/")+"/mcp",
			strings.NewReader(string(requestPayload)),
		)
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("Content-Type", "application/json")

		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		defer response.Body.Close()
		bodyBytes, err := io.ReadAll(response.Body)
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		headers := responseHeaderMap(response.Header)
		*transcript = append(*transcript, map[string]any{
			"step":       "auth/unauthorized-challenge",
			"httpStatus": response.StatusCode,
			"headers":    headers,
			"body":       string(bodyBytes),
		})
		challenge := stringValue(headers["www-authenticate"])
		if response.StatusCode != http.StatusUnauthorized || !strings.Contains(challenge, "resource_metadata=") {
			return failedResult(
				descriptor,
				time.Since(started),
				"unauthorized_initialize_returns_resource_metadata_challenge",
				"unauthorized initialize did not return a protected-resource challenge",
			)
		}
		return passedResult(descriptor, time.Since(started), "unauthorized_initialize_returns_resource_metadata_challenge")
	case "auth-protected-resource-metadata":
		servers, _ := authContext.ProtectedResourceMetadata["authorization_servers"].([]any)
		scopes, _ := authContext.ProtectedResourceMetadata["scopes_supported"].([]any)
		if len(servers) == 0 || !containsString(scopes, args.authScope) {
			return failedResult(
				descriptor,
				time.Since(started),
				"protected_resource_metadata_advertises_auth_server_and_scope",
				"protected resource metadata did not advertise the expected auth server and scope",
			)
		}
		return passedResult(descriptor, time.Since(started), "protected_resource_metadata_advertises_auth_server_and_scope")
	case "auth-authorization-server-metadata":
		grants, _ := authContext.AuthorizationServerMetadata["grant_types_supported"].([]any)
		if !containsString(grants, "authorization_code") ||
			!containsString(grants, "urn:ietf:params:oauth:grant-type:token-exchange") ||
			stringValue(authContext.AuthorizationServerMetadata["authorization_endpoint"]) == "" ||
			stringValue(authContext.AuthorizationServerMetadata["token_endpoint"]) == "" {
			return failedResult(
				descriptor,
				time.Since(started),
				"authorization_server_metadata_advertises_expected_grants",
				"authorization server metadata did not advertise the expected grant types and endpoints",
			)
		}
		return passedResult(descriptor, time.Since(started), "authorization_server_metadata_advertises_expected_grants")
	case "auth-code-initialize":
		extraSession, err := initializeSession(
			ctx,
			client.WithStaticBearer(args.baseURL, authContext.AccessToken, nil),
			transcript,
			"auth-code/",
			nil,
		)
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		closeSession(ctx, extraSession, transcript, "auth-code/")
		return passedResult(descriptor, time.Since(started), "authorization_code_access_token_initializes_session")
	case "auth-token-exchange-initialize":
		exchangedToken, err := auth.ExchangeAccessToken(
			ctx,
			nil,
			args.baseURL,
			args.authScope,
			authContext.AuthorizationServerMetadata,
			authContext.AccessToken,
			func(entry map[string]any) {
				*transcript = append(*transcript, entry)
			},
		)
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		exchangedSession, err := initializeSession(
			ctx,
			client.WithStaticBearer(args.baseURL, exchangedToken, nil),
			transcript,
			"token-exchange/",
			nil,
		)
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		closeSession(ctx, exchangedSession, transcript, "token-exchange/")
		return passedResult(descriptor, time.Since(started), "token_exchange_access_token_initializes_session")
	case "resources-subscribe-updated-notification":
		subscribedURI := "fixture://docs/alpha"
		subscribeExchange, _, err := requestResult(ctx, chioSession, "resources/subscribe", map[string]any{
			"uri": subscribedURI,
		}, "resources/subscribe")
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, subscribeExchange)
		if exchangeStatus(subscribeExchange) != 200 {
			return failedResult(
				descriptor,
				time.Since(started),
				"resources_subscribe_succeeds",
				"resources/subscribe did not succeed",
			)
		}

		triggerExchange, _, err := requestResult(ctx, chioSession, "tools/call", map[string]any{
			"name":      "emit_fixture_notifications",
			"arguments": map[string]any{"uri": subscribedURI},
		}, "notifications/trigger-updated")
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, triggerExchange)
		updateDelivered := false
		for _, message := range exchangeMessages(triggerExchange) {
			if stringValue(message["method"]) != "notifications/resources/updated" {
				continue
			}
			params, _ := message["params"].(map[string]any)
			if stringValue(params["uri"]) == subscribedURI {
				updateDelivered = true
				break
			}
		}
		if exchangeStatus(triggerExchange) != 200 || !updateDelivered {
			return failedResult(
				descriptor,
				time.Since(started),
				"subscribed_resource_update_is_forwarded",
				"wrapped notification flow did not deliver notifications/resources/updated for the subscribed URI",
			)
		}

		return scenarioResult(
			descriptor,
			time.Since(started).Milliseconds(),
			"pass",
			[]map[string]any{
				{"name": "resources_subscribe_succeeds", "status": "pass"},
				{"name": "subscribed_resource_update_is_forwarded", "status": "pass"},
			},
		)
	case "catalog-list-changed-notifications":
		triggerExchange, _, err := requestResult(ctx, chioSession, "tools/call", map[string]any{
			"name":      "emit_fixture_notifications",
			"arguments": map[string]any{"uri": "fixture://docs/alpha"},
		}, "notifications/trigger-catalog")
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, triggerExchange)
		methods := make(map[string]bool)
		for _, message := range exchangeMessages(triggerExchange) {
			method := stringValue(message["method"])
			if method != "" {
				methods[method] = true
			}
		}
		hasAll := methods["notifications/resources/list_changed"] &&
			methods["notifications/tools/list_changed"] &&
			methods["notifications/prompts/list_changed"]
		if exchangeStatus(triggerExchange) != 200 || !hasAll {
			return failedResult(
				descriptor,
				time.Since(started),
				"catalog_list_changed_notifications_are_forwarded",
				"wrapped notification flow did not deliver the expected list-changed notifications",
			)
		}

		return passedResult(
			descriptor,
			time.Since(started),
			"catalog_list_changed_notifications_are_forwarded",
		)
	case "tasks-call-get-result":
		createExchange, createResult, err := requestResult(ctx, chioSession, "tools/call", map[string]any{
			"name":      "echo_text",
			"arguments": map[string]any{"message": "hello from go task peer"},
			"task":      map[string]any{},
		}, "tasks/tools-call")
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, createExchange)
		taskID := nestedString(createResult, "task", "taskId")
		if exchangeStatus(createExchange) != 200 || taskID == "" {
			return failedResult(
				descriptor,
				time.Since(started),
				"task_created",
				"task-augmented tools/call did not return a task id",
			)
		}

		getExchange, getResult, err := requestResult(ctx, chioSession, "tasks/get", map[string]any{
			"taskId": taskID,
		}, "tasks/get")
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, getExchange)
		getStatus := stringValue(getResult["status"])
		if exchangeStatus(getExchange) != 200 || (getStatus != "working" && getStatus != "completed") {
			return failedResult(
				descriptor,
				time.Since(started),
				"tasks_get_returns_working_or_completed",
				fmt.Sprintf("unexpected tasks/get status: %q", getStatus),
			)
		}

		resultExchange, taskResult, err := requestResult(ctx, chioSession, "tasks/result", map[string]any{
			"taskId": taskID,
		}, "tasks/result")
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, resultExchange)
		relatedTaskID := nestedString(taskResult, "_meta", "io.modelcontextprotocol/related-task", "taskId")
		text := firstContentText(taskResult)
		if exchangeStatus(resultExchange) != 200 || relatedTaskID != taskID || text != "hello from go task peer" {
			return failedResult(
				descriptor,
				time.Since(started),
				"tasks_result_returns_related_terminal_payload",
				"tasks/result did not return the expected related-task metadata or payload",
			)
		}

		return scenarioResult(
			descriptor,
			time.Since(started).Milliseconds(),
			"pass",
			[]map[string]any{
				{"name": "task_created", "status": "pass"},
				{"name": "tasks_get_returns_working_or_completed", "status": "pass"},
				{"name": "tasks_result_returns_related_terminal_payload", "status": "pass"},
			},
		)
	case "tasks-cancel":
		createExchange, createResult, err := requestResult(ctx, chioSession, "tools/call", map[string]any{
			"name":      "slow_echo",
			"arguments": map[string]any{"message": "hello from go cancel peer"},
			"task":      map[string]any{},
		}, "tasks/cancel-create")
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, createExchange)
		taskID := nestedString(createResult, "task", "taskId")
		if exchangeStatus(createExchange) != 200 || taskID == "" {
			return failedResult(
				descriptor,
				time.Since(started),
				"task_created",
				"task-augmented slow tools/call did not return a task id",
			)
		}

		cancelExchange, err := chioSession.Request(ctx, "tasks/cancel", map[string]any{
			"taskId": taskID,
		}, nil)
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, map[string]any{
			"step":       "tasks/cancel",
			"request":    cancelExchange.Request,
			"httpStatus": cancelExchange.Status,
			"messages":   cancelExchange.Messages,
		})
		taskCancel, err := terminalResponse(cancelExchange)
		if err != nil {
			return failedResult(
				descriptor,
				time.Since(started),
				"tasks_cancel_terminal_response_present",
				"tasks/cancel did not return a terminal response",
			)
		}
		cancelStatus := stringValue(taskCancel["status"])
		hasStatusNotification := false
		for _, message := range cancelExchange.Messages {
			if stringValue(message["method"]) != "notifications/tasks/status" {
				continue
			}
			params, _ := message["params"].(map[string]any)
			if stringValue(params["taskId"]) == taskID {
				hasStatusNotification = true
				break
			}
		}
		if cancelExchange.Status != 200 || cancelStatus != "cancelled" || !hasStatusNotification {
			return failedResult(
				descriptor,
				time.Since(started),
				"tasks_cancel_marks_cancelled_and_emits_status",
				"tasks/cancel did not mark the task cancelled with a status notification",
			)
		}

		resultExchange, taskResult, err := requestResult(ctx, chioSession, "tasks/result", map[string]any{
			"taskId": taskID,
		}, "tasks/cancel-result")
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, resultExchange)
		relatedTaskID := nestedString(taskResult, "_meta", "io.modelcontextprotocol/related-task", "taskId")
		isError, _ := taskResult["isError"].(bool)
		if exchangeStatus(resultExchange) != 200 || !isError || relatedTaskID != taskID {
			return failedResult(
				descriptor,
				time.Since(started),
				"tasks_result_returns_cancelled_error_payload",
				"tasks/result did not return the expected cancelled error payload",
			)
		}

		return scenarioResult(
			descriptor,
			time.Since(started).Milliseconds(),
			"pass",
			[]map[string]any{
				{"name": "task_created", "status": "pass"},
				{"name": "tasks_cancel_marks_cancelled_and_emits_status", "status": "pass"},
				{"name": "tasks_result_returns_cancelled_error_payload", "status": "pass"},
			},
		)
	case "nested-sampling-create-message":
		response, terminal, err := requestResultWithHandler(ctx, chioSession, "tools/call", map[string]any{
			"name":      "sampled_echo",
			"arguments": map[string]any{"message": "nested callback sampling request"},
		}, "nested/sampling/tool-call", func(ctx context.Context, message map[string]any) error {
			_, err := nestedRouter.Handle(ctx, message, chioSession, "nested/sampling")
			return err
		})
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, response)
		sampledText := nestedString(terminal, "structuredContent", "sampled", "content", "text")
		if exchangeStatus(response) != 200 || countMessagesByMethod(response, "sampling/createMessage") != 1 || sampledText != conformanceSampleText {
			return failedResult(
				descriptor,
				time.Since(started),
				"nested_sampling_request_roundtrips",
				"sampling/createMessage did not round-trip through the remote HTTP edge",
			)
		}
		return passedResult(descriptor, time.Since(started), "nested_sampling_request_roundtrips")
	case "nested-elicitation-form-create":
		response, terminal, err := requestResultWithHandler(ctx, chioSession, "tools/call", map[string]any{
			"name":      "elicited_echo",
			"arguments": map[string]any{"message": "nested callback form elicitation request"},
		}, "nested/elicitation-form/tool-call", func(ctx context.Context, message map[string]any) error {
			_, err := nestedRouter.Handle(ctx, message, chioSession, "nested/elicitation-form")
			return err
		})
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, response)
		action := nestedString(terminal, "structuredContent", "elicited", "action")
		answer := nestedString(terminal, "structuredContent", "elicited", "content", "answer")
		if exchangeStatus(response) != 200 || countMessagesByMethod(response, "elicitation/create") != 1 || action != "accept" || answer != stringValue(conformanceElicitedContent["answer"]) {
			return failedResult(
				descriptor,
				time.Since(started),
				"nested_form_elicitation_roundtrips",
				"form-mode elicitation/create did not round-trip through the remote HTTP edge",
			)
		}
		return passedResult(descriptor, time.Since(started), "nested_form_elicitation_roundtrips")
	case "nested-elicitation-url-create":
		response, terminal, err := requestResultWithHandler(ctx, chioSession, "tools/call", map[string]any{
			"name":      "url_elicited_echo",
			"arguments": map[string]any{"message": "nested callback url elicitation request"},
		}, "nested/elicitation-url/tool-call", func(ctx context.Context, message map[string]any) error {
			_, err := nestedRouter.Handle(ctx, message, chioSession, "nested/elicitation-url")
			return err
		})
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, response)
		elicitationID := nestedString(terminal, "structuredContent", "elicitationId")
		action := nestedString(terminal, "structuredContent", "elicited", "action")
		completionNotification := firstMessageByMethod(response, "notifications/elicitation/complete")
		completionID := nestedString(completionNotification, "params", "elicitationId")
		if exchangeStatus(response) != 200 ||
			countMessagesByMethod(response, "elicitation/create") < 1 ||
			len(completionNotification) == 0 ||
			action != "accept" ||
			elicitationID == "" ||
			completionID != elicitationID {
			return failedResult(
				descriptor,
				time.Since(started),
				"nested_url_elicitation_roundtrips_and_completes",
				"URL-mode elicitation/create did not round-trip and emit completion through the remote HTTP edge",
			)
		}
		return passedResult(descriptor, time.Since(started), "nested_url_elicitation_roundtrips_and_completes")
	case "nested-roots-list":
		response, terminal, err := requestResultWithHandler(ctx, chioSession, "tools/call", map[string]any{
			"name":      "roots_echo",
			"arguments": map[string]any{"message": "nested callback roots request"},
		}, "nested/roots/tool-call", func(ctx context.Context, message map[string]any) error {
			_, err := nestedRouter.Handle(ctx, message, chioSession, "nested/roots")
			return err
		})
		if err != nil {
			return exceptionResult(descriptor, err.Error(), time.Since(started).Milliseconds())
		}
		*transcript = append(*transcript, response)
		firstRootURI := firstStructuredRootURI(terminal)
		if exchangeStatus(response) != 200 || countMessagesByMethod(response, "roots/list") < 1 || firstRootURI != conformanceRoots[0]["uri"] {
			return failedResult(
				descriptor,
				time.Since(started),
				"nested_roots_list_roundtrips",
				"roots/list did not round-trip through the remote HTTP edge",
			)
		}
		return passedResult(descriptor, time.Since(started), "nested_roots_list_roundtrips")
	default:
		return map[string]any{
			"scenarioId":      descriptor.ID,
			"peer":            "go",
			"peerRole":        "client_to_chio_server",
			"deploymentMode":  "remote_http",
			"transport":       "streamable-http",
			"specVersion":     scenarioSpecVersion(descriptor),
			"category":        descriptor.Category,
			"status":          "unsupported",
			"durationMs":      time.Since(started).Milliseconds(),
			"assertions":      []map[string]any{},
			"expectedFailure": false,
			"notes":           fmt.Sprintf("unsupported scenario id %s", descriptor.ID),
		}
	}
}

func requestResult(
	ctx context.Context,
	chioSession *session.Session,
	method string,
	params map[string]any,
	step string,
) (map[string]any, map[string]any, error) {
	return requestResultWithHandler(ctx, chioSession, method, params, step, nil)
}

func requestResultWithHandler(
	ctx context.Context,
	chioSession *session.Session,
	method string,
	params map[string]any,
	step string,
	onMessage session.MessageHandler,
) (map[string]any, map[string]any, error) {
	exchange, err := chioSession.Request(ctx, method, params, onMessage)
	if err != nil {
		return nil, nil, err
	}
	terminal, err := transport.TerminalMessage(exchange.Messages, exchange.Request["id"])
	if err != nil {
		return nil, nil, err
	}
	result, ok := terminal["result"].(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("%s terminal response did not include an object result", method)
	}
	return map[string]any{
		"step":       step,
		"request":    exchange.Request,
		"httpStatus": exchange.Status,
		"messages":   exchange.Messages,
	}, result, nil
}

func initializeSession(
	ctx context.Context,
	chioClient *client.Client,
	transcript *[]map[string]any,
	stepPrefix string,
	capabilities map[string]any,
) (*session.Session, error) {
	chioSession, err := chioClient.Initialize(ctx, client.InitializeOptions{
		Capabilities: capabilities,
		ClientInfo: client.ClientInfo{
			Name:    "chio-conformance-go",
			Version: version.ModuleVersion,
		},
	})
	if err != nil {
		return nil, err
	}

	*transcript = append(*transcript, map[string]any{
		"step":       stepPrefix + "initialize",
		"request":    chioSession.Handshake.InitializeResponse.Request,
		"httpStatus": chioSession.Handshake.InitializeResponse.Status,
		"headers":    chioSession.Handshake.InitializeResponse.Headers,
		"messages":   chioSession.Handshake.InitializeResponse.Messages,
	})
	*transcript = append(*transcript, map[string]any{
		"step":       stepPrefix + "notifications/initialized",
		"request":    chioSession.Handshake.InitializedResponse.Request,
		"httpStatus": chioSession.Handshake.InitializedResponse.Status,
		"messages":   chioSession.Handshake.InitializedResponse.Messages,
	})
	return chioSession, nil
}

func closeSession(
	ctx context.Context,
	chioSession *session.Session,
	transcript *[]map[string]any,
	stepPrefix string,
) {
	if status, err := chioSession.Close(ctx); err == nil {
		*transcript = append(*transcript, map[string]any{
			"step":       stepPrefix + "delete-session",
			"httpStatus": status.Status,
		})
	} else {
		*transcript = append(*transcript, map[string]any{
			"step":  stepPrefix + "delete-session",
			"error": err.Error(),
		})
	}
}

func terminalResponse(exchange transport.RPCExchange) (map[string]any, error) {
	terminal, err := transport.TerminalMessage(exchange.Messages, exchange.Request["id"])
	if err != nil {
		return nil, err
	}
	result, ok := terminal["result"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("terminal response did not include an object result")
	}
	return result, nil
}

func exchangeStatus(exchange map[string]any) int {
	status, ok := exchange["httpStatus"].(int)
	if !ok {
		return 0
	}
	return status
}

func responseHeaderMap(headers http.Header) map[string]any {
	flat := transport.FlattenHeaders(headers)
	result := make(map[string]any, len(flat))
	for key, value := range flat {
		result[key] = value
	}
	return result
}

func exchangeMessages(exchange map[string]any) []map[string]any {
	messages, ok := exchange["messages"].([]map[string]any)
	if ok {
		return messages
	}
	return nil
}

func stringValue(value any) string {
	typed, _ := value.(string)
	return typed
}

func nestedString(root map[string]any, keys ...string) string {
	var current any = root
	for _, key := range keys {
		next, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = next[key]
		if !ok {
			return ""
		}
	}
	return stringValue(current)
}

func firstContentText(result map[string]any) string {
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		return ""
	}
	first, ok := content[0].(map[string]any)
	if !ok {
		return ""
	}
	return stringValue(first["text"])
}

func firstStructuredRootURI(result map[string]any) string {
	structuredContent, ok := result["structuredContent"].(map[string]any)
	if !ok {
		return ""
	}
	roots, ok := structuredContent["roots"].([]any)
	if !ok || len(roots) == 0 {
		return ""
	}
	first, ok := roots[0].(map[string]any)
	if !ok {
		return ""
	}
	return stringValue(first["uri"])
}

func countMessagesByMethod(exchange map[string]any, method string) int {
	count := 0
	for _, message := range exchangeMessages(exchange) {
		if stringValue(message["method"]) == method {
			count += 1
		}
	}
	return count
}

func firstMessageByMethod(exchange map[string]any, method string) map[string]any {
	for _, message := range exchangeMessages(exchange) {
		if stringValue(message["method"]) == method {
			return message
		}
	}
	return nil
}

func buildNestedCallbackRouter(transcript *[]map[string]any) *nested.Router {
	return nested.NewRouter(func(entry map[string]any) {
		*transcript = append(*transcript, entry)
	}).Register(
		"sampling/createMessage",
		"sampling-response",
		func(message map[string]any, _ *session.Session) map[string]any {
			return nested.SamplingTextResult(message, conformanceSampleText, "chio-conformance-go-model", "")
		},
	).Register(
		"elicitation/create",
		"elicitation-response",
		func(message map[string]any, _ *session.Session) map[string]any {
			params, _ := message["params"].(map[string]any)
			if stringValue(params["mode"]) == "url" {
				return nested.ElicitationAcceptResult(message, nil)
			}
			return nested.ElicitationAcceptResult(message, conformanceElicitedContent)
		},
	).Register(
		"roots/list",
		"roots-response",
		func(message map[string]any, _ *session.Session) map[string]any {
			return nested.RootsListResult(message, conformanceRoots)
		},
	)
}

func conformanceClientCapabilities() map[string]any {
	return map[string]any{
		"sampling": map[string]any{
			"context": map[string]any{},
			"tools":   map[string]any{},
		},
		"elicitation": map[string]any{
			"form": map[string]any{},
			"url":  map[string]any{},
		},
		"roots": map[string]any{
			"listChanged": true,
		},
	}
}

func scenarioRequiresDedicatedSession(descriptor scenario) bool {
	return strings.HasPrefix(descriptor.ID, "nested-")
}

func resolveAuth(
	ctx context.Context,
	args cliArgs,
	transcript *[]map[string]any,
) (authContext, error) {
	if args.authMode != "oauth-local" {
		return authContext{
			Mode:        "static-bearer",
			AccessToken: args.authToken,
		}, nil
	}

	oauthContext, err := auth.ResolveOAuthAccessToken(
		ctx,
		nil,
		args.baseURL,
		args.authScope,
		func(entry map[string]any) {
			*transcript = append(*transcript, entry)
		},
	)
	if err != nil {
		return authContext{}, err
	}
	return authContext{
		Mode:                        "oauth-local",
		AccessToken:                 stringValue(oauthContext["access_token"]),
		ProtectedResourceMetadata:   mapValue(oauthContext["protected_resource_metadata"]),
		AuthorizationServerMetadata: mapValue(oauthContext["authorization_server_metadata"]),
	}, nil
}

func containsString(values []any, expected string) bool {
	for _, value := range values {
		if stringValue(value) == expected {
			return true
		}
	}
	return false
}

func mapValue(value any) map[string]any {
	typed, _ := value.(map[string]any)
	return typed
}

func scenarioSpecVersion(descriptor scenario) string {
	if len(descriptor.SpecVersions) > 0 {
		return descriptor.SpecVersions[0]
	}
	return "2025-11-25"
}

func passedResult(descriptor scenario, duration time.Duration, assertionName string) map[string]any {
	return scenarioResult(
		descriptor,
		duration.Milliseconds(),
		"pass",
		[]map[string]any{{"name": assertionName, "status": "pass"}},
	)
}

func failedResult(descriptor scenario, duration time.Duration, assertionName string, message string) map[string]any {
	result := scenarioResult(
		descriptor,
		duration.Milliseconds(),
		"fail",
		[]map[string]any{{"name": assertionName, "status": "fail", "message": message}},
	)
	result["failureKind"] = "assertion-failed"
	result["failureMessage"] = message
	return result
}

func exceptionResult(descriptor scenario, message string, durationMs int64) map[string]any {
	result := scenarioResult(
		descriptor,
		durationMs,
		"fail",
		[]map[string]any{{"name": "scenario_execution", "status": "fail", "message": message}},
	)
	result["failureKind"] = "exception"
	result["failureMessage"] = message
	return result
}

func scenarioResult(descriptor scenario, durationMs int64, status string, assertions []map[string]any) map[string]any {
	return map[string]any{
		"scenarioId":      descriptor.ID,
		"peer":            "go",
		"peerRole":        "client_to_chio_server",
		"deploymentMode":  "remote_http",
		"transport":       "streamable-http",
		"specVersion":     scenarioSpecVersion(descriptor),
		"category":        descriptor.Category,
		"status":          status,
		"durationMs":      durationMs,
		"assertions":      assertions,
		"expectedFailure": status == "xfail",
	}
}

func writeOutputs(
	resultsOutput string,
	artifactsDir string,
	transcript []map[string]any,
	results []map[string]any,
) error {
	if err := os.MkdirAll(artifactsDir, 0o755); err != nil {
		return err
	}
	transcriptPath := filepath.Join(artifactsDir, "transcript.jsonl")
	transcriptFile, err := os.Create(transcriptPath)
	if err != nil {
		return err
	}
	for _, entry := range transcript {
		line, err := json.Marshal(entry)
		if err != nil {
			transcriptFile.Close()
			return err
		}
		if _, err := transcriptFile.Write(append(line, '\n')); err != nil {
			transcriptFile.Close()
			return err
		}
	}
	if err := transcriptFile.Close(); err != nil {
		return err
	}

	for _, result := range results {
		result["artifacts"] = map[string]any{"transcript": transcriptPath}
	}
	if err := os.MkdirAll(filepath.Dir(resultsOutput), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(resultsOutput, append(body, '\n'), 0o644)
}
