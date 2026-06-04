package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	chio "github.com/backbay-labs/chio/sdks/go/chio-go-http"
	"github.com/go-chi/chi/v5"
)

type echoRequest struct {
	Message *string `json:"message"`
	Count   *int    `json:"count,omitempty"`
}

type echoResponse struct {
	Message string `json:"message"`
	Count   int    `json:"count"`
}

func main() {
	handler := protectedHandler(envOrDefault("CHIO_SIDECAR_URL", "http://127.0.0.1:9090"))
	addr := "127.0.0.1:" + envOrDefault("HELLO_CHI_PORT", "8013")
	log.Printf("hello-chi listening on http://%s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
}

func protectedHandler(sidecarURL string) http.Handler {
	return chio.Protect(
		newRouter(),
		chio.WithSidecarURL(sidecarURL),
	)
}

func newRouter() http.Handler {
	router := chi.NewRouter()

	router.Get("/healthz", healthz)
	router.Get("/hello", hello)
	router.Post("/echo", echo)

	return router
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func hello(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"message": "hello from chi"})
}

func echo(w http.ResponseWriter, r *http.Request) {
	payload, err := parseEchoRequest(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, payload)
}

func parseEchoRequest(body io.Reader) (echoResponse, error) {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()

	var payload echoRequest
	if err := decoder.Decode(&payload); err != nil {
		return echoResponse{}, err
	}

	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return echoResponse{}, fmt.Errorf("body must contain a single JSON object")
	}

	if payload.Message == nil || *payload.Message == "" {
		return echoResponse{}, fmt.Errorf("message must be a non-empty string")
	}

	count := 1
	if payload.Count != nil {
		count = *payload.Count
	}
	if count < 1 {
		return echoResponse{}, fmt.Errorf("count must be an integer greater than or equal to 1")
	}

	return echoResponse{
		Message: *payload.Message,
		Count:   count,
	}, nil
}

func envOrDefault(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
