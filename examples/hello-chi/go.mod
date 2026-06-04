module hello-chi

go 1.21

require (
	github.com/backbay-labs/chio/sdks/go/chio-go-http v0.0.0
	github.com/go-chi/chi/v5 v5.2.3
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/oapi-codegen/runtime v1.2.0 // indirect
)

replace github.com/backbay-labs/chio/sdks/go/chio-go-http => ../../sdks/go/chio-go-http
