package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type TranscriptHook func(map[string]any)

type JSONResponse struct {
	Status  int
	Headers map[string]string
	Body    map[string]any
}

type OAuthMetadata struct {
	AuthorizationServerMetadata map[string]any
	ProtectedResourceMetadata   map[string]any
}

type AuthorizationCodeFlowOptions struct {
	ClientID     string
	CodeVerifier string
	RedirectURI  string
	State        string
}

func GetJSON(ctx context.Context, httpClient *http.Client, urlString string) (JSONResponse, error) {
	client := coalesceHTTPClient(httpClient)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, urlString, nil)
	if err != nil {
		return JSONResponse{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return JSONResponse{}, err
	}
	defer response.Body.Close()
	body, err := decodeJSONObject(response.Body)
	if err != nil {
		return JSONResponse{}, err
	}
	return JSONResponse{
		Status:  response.StatusCode,
		Headers: lowerCaseHeaders(response.Header),
		Body:    body,
	}, nil
}

func PKCEChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func AuthorizationServerMetadataURL(baseURL string, issuer string) string {
	parsed, err := url.Parse(issuer)
	trimmedPath := ""
	if err == nil {
		trimmedPath = strings.Trim(parsed.Path, "/")
	} else {
		trimmedPath = strings.Trim(issuer, "/")
	}
	if trimmedPath != "" {
		return strings.TrimRight(baseURL, "/") + "/.well-known/oauth-authorization-server/" + trimmedPath
	}
	return strings.TrimRight(baseURL, "/") + "/.well-known/oauth-authorization-server"
}

func DiscoverOAuthMetadata(
	ctx context.Context,
	httpClient *http.Client,
	baseURL string,
	emit TranscriptHook,
) (OAuthMetadata, error) {
	protectedResource, err := GetJSON(ctx, httpClient, strings.TrimRight(baseURL, "/")+"/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		return OAuthMetadata{}, err
	}
	if emit != nil {
		emit(map[string]any{
			"step":       "auth/protected-resource-metadata",
			"httpStatus": protectedResource.Status,
			"headers":    protectedResource.Headers,
			"body":       protectedResource.Body,
		})
	}
	rawIssuers, ok := protectedResource.Body["authorization_servers"].([]any)
	if !ok || len(rawIssuers) == 0 {
		return OAuthMetadata{}, fmt.Errorf("protected resource metadata did not advertise an authorization server")
	}
	issuer, ok := rawIssuers[0].(string)
	if !ok || issuer == "" {
		return OAuthMetadata{}, fmt.Errorf("protected resource metadata did not advertise an authorization server")
	}
	authorizationServer, err := GetJSON(ctx, httpClient, AuthorizationServerMetadataURL(baseURL, issuer))
	if err != nil {
		return OAuthMetadata{}, err
	}
	if emit != nil {
		emit(map[string]any{
			"step":       "auth/authorization-server-metadata",
			"httpStatus": authorizationServer.Status,
			"headers":    authorizationServer.Headers,
			"body":       authorizationServer.Body,
		})
	}
	return OAuthMetadata{
		AuthorizationServerMetadata: authorizationServer.Body,
		ProtectedResourceMetadata:   protectedResource.Body,
	}, nil
}

func PerformAuthorizationCodeFlow(
	ctx context.Context,
	httpClient *http.Client,
	baseURL string,
	authScope string,
	authorizationServerMetadata map[string]any,
	emit TranscriptHook,
	options *AuthorizationCodeFlowOptions,
) (string, error) {
	flowOptions := coalesceFlowOptions(options)
	resource := strings.TrimRight(baseURL, "/") + "/mcp"
	authorizationEndpoint := stringOrDefault(
		authorizationServerMetadata["authorization_endpoint"],
		strings.TrimRight(baseURL, "/")+"/oauth/authorize",
	)
	tokenEndpoint := stringOrDefault(
		authorizationServerMetadata["token_endpoint"],
		strings.TrimRight(baseURL, "/")+"/oauth/token",
	)

	authorizeQuery := url.Values{
		"response_type":         []string{"code"},
		"client_id":             []string{flowOptions.ClientID},
		"redirect_uri":          []string{flowOptions.RedirectURI},
		"state":                 []string{flowOptions.State},
		"resource":              []string{resource},
		"scope":                 []string{authScope},
		"code_challenge":        []string{PKCEChallenge(flowOptions.CodeVerifier)},
		"code_challenge_method": []string{"S256"},
	}
	authorizeRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		authorizationEndpoint+"?"+authorizeQuery.Encode(),
		nil,
	)
	if err != nil {
		return "", err
	}
	client := coalesceHTTPClient(httpClient)
	authorizeResponse, err := client.Do(authorizeRequest)
	if err != nil {
		return "", err
	}
	authorizeBodyBytes, err := io.ReadAll(authorizeResponse.Body)
	authorizeResponse.Body.Close()
	if err != nil {
		return "", err
	}
	authorizeBody := string(authorizeBodyBytes)
	if emit != nil {
		emit(map[string]any{
			"step":       "auth/authorize-page",
			"httpStatus": authorizeResponse.StatusCode,
			"headers":    lowerCaseHeaders(authorizeResponse.Header),
			"body":       authorizeBody,
		})
	}
	if authorizeResponse.StatusCode != http.StatusOK || !strings.Contains(authorizeBody, "Approve") {
		return "", fmt.Errorf("authorization endpoint did not return an approval page")
	}

	approvalForm := url.Values{
		"response_type":         []string{"code"},
		"client_id":             []string{flowOptions.ClientID},
		"redirect_uri":          []string{flowOptions.RedirectURI},
		"state":                 []string{flowOptions.State},
		"resource":              []string{resource},
		"scope":                 []string{authScope},
		"code_challenge":        []string{PKCEChallenge(flowOptions.CodeVerifier)},
		"code_challenge_method": []string{"S256"},
		"decision":              []string{"approve"},
	}
	approvalRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		authorizationEndpoint,
		strings.NewReader(approvalForm.Encode()),
	)
	if err != nil {
		return "", err
	}
	approvalRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	noRedirectClient := cloneHTTPClient(client)
	noRedirectClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	approvalResponse, err := noRedirectClient.Do(approvalRequest)
	if err != nil {
		return "", err
	}
	defer approvalResponse.Body.Close()
	if emit != nil {
		emit(map[string]any{
			"step":       "auth/authorize-approve",
			"httpStatus": approvalResponse.StatusCode,
			"headers":    lowerCaseHeaders(approvalResponse.Header),
		})
	}
	if approvalResponse.StatusCode < 300 || approvalResponse.StatusCode >= 400 {
		return "", fmt.Errorf("authorization approval did not redirect with a code")
	}
	location := approvalResponse.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("authorization approval did not provide a redirect location")
	}
	redirectURL, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	code := redirectURL.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("authorization approval redirect did not include a code")
	}

	tokenForm := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{flowOptions.RedirectURI},
		"client_id":     []string{flowOptions.ClientID},
		"code_verifier": []string{flowOptions.CodeVerifier},
		"resource":      []string{resource},
	}
	tokenRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		tokenEndpoint,
		strings.NewReader(tokenForm.Encode()),
	)
	if err != nil {
		return "", err
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse, err := client.Do(tokenRequest)
	if err != nil {
		return "", err
	}
	defer tokenResponse.Body.Close()
	tokenBody, err := decodeJSONObject(tokenResponse.Body)
	if err != nil {
		return "", err
	}
	if emit != nil {
		emit(map[string]any{
			"step":       "auth/token",
			"httpStatus": tokenResponse.StatusCode,
			"headers":    lowerCaseHeaders(tokenResponse.Header),
			"body":       tokenBody,
		})
	}
	accessToken, ok := tokenBody["access_token"].(string)
	if tokenResponse.StatusCode != http.StatusOK || !ok || accessToken == "" {
		return "", fmt.Errorf("authorization code exchange did not return an access token")
	}
	return accessToken, nil
}

func ExchangeAccessToken(
	ctx context.Context,
	httpClient *http.Client,
	baseURL string,
	authScope string,
	authorizationServerMetadata map[string]any,
	accessToken string,
	emit TranscriptHook,
) (string, error) {
	tokenEndpoint := stringOrDefault(
		authorizationServerMetadata["token_endpoint"],
		strings.TrimRight(baseURL, "/")+"/oauth/token",
	)
	form := url.Values{
		"grant_type":         []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      []string{accessToken},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           []string{strings.TrimRight(baseURL, "/") + "/mcp"},
		"scope":              []string{authScope},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := coalesceHTTPClient(httpClient)
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := decodeJSONObject(response.Body)
	if err != nil {
		return "", err
	}
	if emit != nil {
		emit(map[string]any{
			"step":       "auth/token-exchange",
			"httpStatus": response.StatusCode,
			"headers":    lowerCaseHeaders(response.Header),
			"body":       body,
		})
	}
	token, ok := body["access_token"].(string)
	if response.StatusCode != http.StatusOK || !ok || token == "" {
		return "", fmt.Errorf("token exchange did not return an access token")
	}
	return token, nil
}

func ResolveOAuthAccessToken(
	ctx context.Context,
	httpClient *http.Client,
	baseURL string,
	authScope string,
	emit TranscriptHook,
) (map[string]any, error) {
	metadata, err := DiscoverOAuthMetadata(ctx, httpClient, baseURL, emit)
	if err != nil {
		return nil, err
	}
	accessToken, err := PerformAuthorizationCodeFlow(
		ctx,
		httpClient,
		baseURL,
		authScope,
		metadata.AuthorizationServerMetadata,
		emit,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"access_token":                  accessToken,
		"protected_resource_metadata":   metadata.ProtectedResourceMetadata,
		"authorization_server_metadata": metadata.AuthorizationServerMetadata,
	}, nil
}

func lowerCaseHeaders(headers http.Header) map[string]string {
	result := make(map[string]string, len(headers))
	for key, values := range headers {
		if len(values) == 0 {
			continue
		}
		result[strings.ToLower(key)] = values[0]
	}
	return result
}

func decodeJSONObject(reader io.Reader) (map[string]any, error) {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	var body map[string]any
	if err := decoder.Decode(&body); err != nil {
		return nil, err
	}
	return body, nil
}

func coalesceHTTPClient(httpClient *http.Client) *http.Client {
	if httpClient == nil {
		return http.DefaultClient
	}
	return httpClient
}

func cloneHTTPClient(httpClient *http.Client) *http.Client {
	clone := *httpClient
	return &clone
}

func stringOrDefault(value any, fallback string) string {
	stringValue, ok := value.(string)
	if !ok || stringValue == "" {
		return fallback
	}
	return stringValue
}

func coalesceFlowOptions(options *AuthorizationCodeFlowOptions) AuthorizationCodeFlowOptions {
	if options == nil {
		return AuthorizationCodeFlowOptions{
			ClientID:     "https://client.example/app",
			CodeVerifier: "chio-go-verifier",
			RedirectURI:  "http://localhost:7777/callback",
			State:        "chio-go-state",
		}
	}
	merged := *options
	if merged.ClientID == "" {
		merged.ClientID = "https://client.example/app"
	}
	if merged.CodeVerifier == "" {
		merged.CodeVerifier = "chio-go-verifier"
	}
	if merged.RedirectURI == "" {
		merged.RedirectURI = "http://localhost:7777/callback"
	}
	if merged.State == "" {
		merged.State = "chio-go-state"
	}
	return merged
}
