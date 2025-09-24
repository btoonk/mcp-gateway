package main

import (
    "context"
    "log"

    "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Params and handler for a demo tool
type ServerListParams struct{}

type ServerList struct {
    Servers []string `json:"servers"`
}

func getServers(_ context.Context, _ *mcp.CallToolRequest, _ ServerListParams) (*mcp.CallToolResult, any, error) {
    return nil, ServerList{Servers: []string{"alpha", "beta", "gamma"}}, nil
}

func main() {
    server := mcp.NewServer(&mcp.Implementation{
        Name:    "demo-stdio-upstream",
        Version: "0.1.0",
    }, &mcp.ServerOptions{HasTools: true})

    mcp.AddTool(server, &mcp.Tool{
        Name:        "get_servers",
        Title:       "Get Servers",
        Description: "Return a demo list of servers",
    }, getServers)

    if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
        log.Fatalf("stdio server error: %v", err)
    }
}

