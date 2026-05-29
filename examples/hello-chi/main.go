package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	chio "github.com/backbay-labs/chio/sdks/go/chio-go-http"
	"github.com/go-chi/chi/v5"
)

type echoRequest struct {
	Message string `json:"message"`
	Count   int    `json:"count"`
}

type echoResponse struct {
	Message string `json:"message"`
	Count   int    `json:"count"`
}

func main() {
	router := chi.NewRouter()

	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	router.Get("/hello", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "hello from chi"})
	})

	router.Post("/echo", func(w http.ResponseWriter, r *http.Request) {
		var payload echoRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, echoResponse{
			Message: payload.Message,
			Count:   payload.Count,
		})
	})

	handler := chio.Protect(
		router,
		chio.WithSidecarURL(envOrDefault("CHIO_SIDECAR_URL", "http://127.0.0.1:9090")),
	)

	addr := "127.0.0.1:" + envOrDefault("HELLO_CHI_PORT", "8013")
	log.Printf("hello-chi listening on http://%s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
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
