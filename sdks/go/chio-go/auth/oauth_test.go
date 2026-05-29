package auth_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/backbay-labs/chio/sdks/go/chio-go/auth"
)

func TestPKCEChallengeAndMetadataURL(t *testing.T) {
	if challenge := auth.PKCEChallenge("abc"); challenge != "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" {
		t.Fatalf("unexpected PKCE challenge: %s", challenge)
	}
	url := auth.AuthorizationServerMetadataURL("http://127.0.0.1:8080", "http://127.0.0.1:8080/oauth")
	if url != "http://127.0.0.1:8080/.well-known/oauth-authorization-server/oauth" {
		t.Fatalf("unexpected metadata URL: %s", url)
	}
}

func TestDiscoverResolveAndExchangeOAuthFlow(t *testing.T) {
	transcript := make([]map[string]any, 0)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/oauth-protected-resource/mcp":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"authorization_servers": []string{server.URL + "/oauth"},
				"scopes_supported":      []string{"mcp:invoke"},
			})
		case "/.well-known/oauth-authorization-server/oauth":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"authorization_endpoint": server.URL + "/oauth/authorize",
				"token_endpoint":         server.URL + "/oauth/token",
				"grant_types_supported": []string{
					"authorization_code",
					"urn:ietf:params:oauth:grant-type:token-exchange",
				},
			})
		case "/oauth/authorize":
			if request.Method == http.MethodGet {
				writer.Header().Set("Content-Type", "text/html")
				_, _ = writer.Write([]byte("<html><body><button>Approve</button></body></html>"))
				return
			}
			if err := request.ParseForm(); err != nil {
				t.Fatalf("failed to parse form: %v", err)
			}
			redirectURI := request.Form.Get("redirect_uri")
			state := request.Form.Get("state")
			http.Redirect(writer, request, redirectURI+"?code=fixture-code&state="+state, http.StatusFound)
		case "/oauth/token":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("failed to read token body: %v", err)
			}
			values, err := urlParseQuery(string(body))
			if err != nil {
				t.Fatalf("failed to parse token body: %v", err)
			}
			writer.Header().Set("Content-Type", "application/json")
			if values.Get("grant_type") == "authorization_code" {
				_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "auth-code-token"})
				return
			}
			if values.Get("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange" {
				_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "exchanged-token"})
				return
			}
			t.Fatalf("unexpected token grant type: %s", values.Get("grant_type"))
		default:
			t.Fatalf("unexpected path: %s", request.URL.Path)
		}
	}))
	defer server.Close()

	metadata, err := auth.DiscoverOAuthMetadata(context.Background(), server.Client(), server.URL, func(entry map[string]any) {
		transcript = append(transcript, entry)
	})
	if err != nil {
		t.Fatalf("DiscoverOAuthMetadata failed: %v", err)
	}
	if len(transcript) != 2 {
		t.Fatalf("expected 2 transcript entries after discovery, got %d", len(transcript))
	}

	accessToken, err := auth.PerformAuthorizationCodeFlow(
		context.Background(),
		server.Client(),
		server.URL,
		"mcp:invoke",
		metadata.AuthorizationServerMetadata,
		func(entry map[string]any) {
			transcript = append(transcript, entry)
		},
		&auth.AuthorizationCodeFlowOptions{
			ClientID:     "https://client.example/app",
			CodeVerifier: "abc",
			RedirectURI:  "http://localhost:7777/callback",
			State:        "fixture-state",
		},
	)
	if err != nil {
		t.Fatalf("PerformAuthorizationCodeFlow failed: %v", err)
	}
	if accessToken != "auth-code-token" {
		t.Fatalf("unexpected authorization code token: %s", accessToken)
	}

	exchangedToken, err := auth.ExchangeAccessToken(
		context.Background(),
		server.Client(),
		server.URL,
		"mcp:invoke",
		metadata.AuthorizationServerMetadata,
		accessToken,
		func(entry map[string]any) {
			transcript = append(transcript, entry)
		},
	)
	if err != nil {
		t.Fatalf("ExchangeAccessToken failed: %v", err)
	}
	if exchangedToken != "exchanged-token" {
		t.Fatalf("unexpected exchanged token: %s", exchangedToken)
	}

	resolved, err := auth.ResolveOAuthAccessToken(
		context.Background(),
		server.Client(),
		server.URL,
		"mcp:invoke",
		nil,
	)
	if err != nil {
		t.Fatalf("ResolveOAuthAccessToken failed: %v", err)
	}
	if resolved["access_token"] != "auth-code-token" {
		t.Fatalf("unexpected resolved token: %#v", resolved)
	}
}

func urlParseQuery(encoded string) (mapQueryValues, error) {
	values, err := url.ParseQuery(encoded)
	return mapQueryValues(values), err
}

type mapQueryValues map[string][]string

func (values mapQueryValues) Get(key string) string {
	entries := values[key]
	if len(entries) == 0 {
		return ""
	}
	return entries[0]
}
