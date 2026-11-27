package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/dispatch"
	internaldns "github.com/FrankXLT/mcp-adv-netutils/internal/dns"
	"github.com/FrankXLT/mcp-adv-netutils/internal/http_ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/resolver"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/FrankXLT/mcp-adv-netutils/internal/tls"
	"github.com/FrankXLT/mcp-adv-netutils/internal/transport"
	"github.com/FrankXLT/mcp-adv-netutils/internal/whois"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// NetUtilsConfig contains configuration for the network utilities, security guards,
// persistence, cron scheduler, and unified tool dispatcher.
type NetUtilsConfig struct {
	QueryConfig            *internaldns.QueryConfig
	WhoisConfig            *whois.Config
	ResolverConfig         *resolver.Config
	PingConfig             *ping.Config
	HTTPPingConfig         *http_ping.Config
	TLSConfig              *tls.Config
	Version                string
	Dispatcher             *dispatch.Dispatcher
	Guard                  *security.TargetGuard
	Store                  *store.JobStore
	Scheduler              *cronmon.Scheduler
	Deadbolt               *security.Deadbolt
	DefaultStdio           bool
	AllowLockedCronSummary bool
}

const (
	serverTitle    = "Advanced Network Utilities"
	defaultVersion = "2.0.0"
	defaultStyle   = "default"
)

// SetupTools creates and configures the MCP server with all 33 network utility tools.
func SetupTools(config *NetUtilsConfig) (*mcpserver.MCPServer, error) {
	s, _, err := SetupServerWithDispatcher(config)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// SetupServerWithDispatcher creates an MCP server and returns it alongside the backing Dispatcher.
func SetupServerWithDispatcher(config *NetUtilsConfig) (*mcpserver.MCPServer, *dispatch.Dispatcher, error) {
	if config == nil {
		config = &NetUtilsConfig{Version: defaultVersion}
	}
	version := strings.TrimSpace(config.Version)
	if version == "" {
		version = defaultVersion
	}

	disp := config.Dispatcher
	if disp == nil {
		var err error
		disp, err = dispatch.New(dispatch.Config{
			Version:                version,
			Deadbolt:               config.Deadbolt,
			Guard:                  config.Guard,
			Store:                  config.Store,
			Scheduler:              config.Scheduler,
			DNS:                    config.QueryConfig,
			Whois:                  config.WhoisConfig,
			Resolver:               config.ResolverConfig,
			Ping:                   config.PingConfig,
			HTTP:                   config.HTTPPingConfig,
			TLS:                    config.TLSConfig,
			AllowLockedCronSummary: config.AllowLockedCronSummary,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("create dispatcher: %w", err)
		}
	}

	s := mcpserver.NewMCPServer(
		serverTitle,
		version,
		mcpserver.WithRecovery(),
	)

	specs := buildAllToolSpecs()
	for i := range specs {
		spec := &specs[i]
		s.AddTool(*spec, newDispatchHandler(disp, spec.Name, config.DefaultStdio))
	}

	return s, disp, nil
}

func newDispatchHandler(disp *dispatch.Dispatcher, toolName string, defaultStdio bool) mcpserver.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		style := strings.TrimSpace(req.GetString("style", defaultStyle))
		if style == "" {
			style = defaultStyle
		}
		skipDeadbolt := defaultStdio && transport.DoorwayFromContext(ctx) == ""

		out, err := disp.Dispatch(ctx, dispatch.Request{
			Tool:         toolName,
			Args:         args,
			Style:        style,
			Source:       "mcp",
			SkipDeadbolt: skipDeadbolt,
		})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(out.Output), nil
	}
}
