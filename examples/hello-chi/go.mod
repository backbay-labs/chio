module hello-chi

go 1.21

require (
	github.com/backbay-labs/chio/sdks/go/chio-go-http v0.0.0
	github.com/go-chi/chi/v5 v5.2.3
)

require github.com/google/uuid v1.6.0 // indirect

replace github.com/backbay-labs/chio/sdks/go/chio-go-http => ../../sdks/go/chio-go-http
