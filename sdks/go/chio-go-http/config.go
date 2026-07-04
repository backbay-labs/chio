package chio

import (
	"net/http"
	"os"
)

// Config holds the Chio middleware configuration.
type Config struct {
	// SidecarURL is the base URL of the Chio sidecar kernel.
	// Defaults to CHIO_SIDECAR_URL env var or "http://127.0.0.1:9090".
	SidecarURL string

	// ConfigFile is the path to the chio.yaml configuration file.
	// The sidecar reads route patterns and policies from this file.
	ConfigFile string

	// TimeoutSeconds is the HTTP timeout for sidecar calls. Default: 5.
	TimeoutSeconds int

	// IdentityExtractor extracts caller identity from an HTTP request.
	// Defaults to header-based extraction (Bearer, API key, cookie).
	IdentityExtractor IdentityExtractorFunc

	// RouteResolver maps a request method and path to a route pattern.
	// Defaults to returning the raw path.
	RouteResolver RouteResolverFunc
}

// IdentityExtractorFunc extracts a CallerIdentity from an HTTP request.
type IdentityExtractorFunc func(r *http.Request) CallerIdentity

// RouteResolverFunc maps an HTTP method and raw path to a route pattern
// (e.g., "/pets/42" -> "/pets/{petId}").
type RouteResolverFunc func(method, path string) string

// Option configures the Chio middleware.
type Option func(*Config)

// defaultConfig returns the default configuration.
func defaultConfig() Config {
	sidecarURL := os.Getenv("CHIO_SIDECAR_URL")
	if sidecarURL == "" {
		sidecarURL = "http://127.0.0.1:9090"
	}
	return Config{
		SidecarURL:        sidecarURL,
		TimeoutSeconds:    5,
		IdentityExtractor: DefaultIdentityExtractor,
		RouteResolver:     defaultRouteResolver,
	}
}

// defaultRouteResolver returns the raw path as the route pattern.
func defaultRouteResolver(_method, path string) string {
	return path
}

// ConfigFile sets the path to the chio.yaml configuration file.
func ConfigFile(path string) Option {
	return func(c *Config) {
		c.ConfigFile = path
	}
}

// WithSidecarURL sets the sidecar base URL.
func WithSidecarURL(url string) Option {
	return func(c *Config) {
		c.SidecarURL = url
	}
}

// WithTimeout sets the sidecar HTTP timeout in seconds.
func WithTimeout(seconds int) Option {
	return func(c *Config) {
		c.TimeoutSeconds = seconds
	}
}

// WithIdentityExtractor sets a custom identity extraction function.
func WithIdentityExtractor(fn IdentityExtractorFunc) Option {
	return func(c *Config) {
		c.IdentityExtractor = fn
	}
}

// WithRouteResolver sets a custom route pattern resolver.
func WithRouteResolver(fn RouteResolverFunc) Option {
	return func(c *Config) {
		c.RouteResolver = fn
	}
}
