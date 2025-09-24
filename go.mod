module github.com/btoonk/mcp-gateway

go 1.23.0

require (
	github.com/modelcontextprotocol/go-sdk v0.0.0
	github.com/golang-jwt/jwt/v5 v5.2.2
)

require (
	github.com/google/jsonschema-go v0.3.0 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
)

replace github.com/modelcontextprotocol/go-sdk => ./go-sdk
